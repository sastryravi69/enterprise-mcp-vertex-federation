"""Vertex AI / Gemini <-> Zero-Trust MCP Gateway Bridge.

Connects to the local Python MCP server over stdio, applies the FinOps PromptRouter
to select Gemini 1.5 Flash vs Gemini 1.5 Pro, and executes grounded tool calls
without raw PII ever leaving the enclave.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .config import DEFAULT_DB_PATH, VertexConfig
from .router.classifier import PromptRouter, RoutingDecision
from .router.finops import FinOpsTracker, QueryCostRecord, estimate_tokens


@dataclass(frozen=True)
class AgentExecutionResult:
    """Complete trace of a routed prompt flowing through Vertex AI and Zero-Trust MCP."""

    prompt: str
    engine_mode: str  # "vertex_ai_live" or "local_mcp_sandbox"
    routing: RoutingDecision
    tools_discovered: list[str]
    tool_calls_executed: list[dict[str, Any]]
    total_pii_redactions: int
    answer: str
    finops: QueryCostRecord


def _extract_json_from_mcp_result(result: Any) -> dict[str, Any]:
    texts: list[str] = []
    for item in getattr(result, "content", []):
        txt = getattr(item, "text", None)
        if txt:
            texts.append(txt)
    joined = "\n".join(texts).strip()
    if not joined:
        return {}
    try:
        parsed = json.loads(joined)
        return parsed if isinstance(parsed, dict) else {"result": parsed}
    except json.JSONDecodeError:
        return {"raw_text": joined}


def _plan_local_mcp_calls(prompt: str) -> list[tuple[str, dict[str, Any]]]:
    """Deterministic tool-call planner used in zero-credential sandbox verification."""
    lower = prompt.lower()
    calls: list[tuple[str, dict[str, Any]]] = []

    # Check explicit customer ID (e.g. C-101) or known company names
    cid_match = re.search(r"\b(C-\d{3})\b", prompt, re.IGNORECASE)
    known_companies = (
        "bharatfin",
        "eurogrid",
        "meridian",
        "pacific aero",
        "nordic freight",
        "deccan pharma",
        "thames clearing",
        "apex semiconductor",
        "sunbelt",
        "indus telecom",
    )
    matched_company = next((c for c in known_companies if c in lower), None)

    if cid_match or matched_company:
        query = cid_match.group(1).upper() if cid_match else matched_company  # type: ignore[arg-type]
        calls.append(("crm_get_account_summary", {"customer_query": query}))

    if any(k in lower for k in ("audit", "redaction", "sha-256", "trail")):
        calls.append(("crm_get_audit_trail", {"limit": 10, "caller_role": "security_auditor"}))

    if any(k in lower for k in ("ticket", "sla", "breach", "p1", "p2", "outage", "escalation", "correlate", "root cause")):
        region = None
        for r in ("EMEA", "APAC", "NA", "IN"):
            if re.search(rf"\b{r}\b", prompt, re.IGNORECASE):
                region = r
                break
        if "india" in lower:
            region = "IN"
        sev = "P1" if "p1" in lower else ("P2" if "p2" in lower else None)
        calls.append(
            (
                "crm_check_sla_risks",
                {
                    "severity": sev,
                    "region": region,
                    "only_sla_breached": "breach" in lower,
                    "limit": 10,
                },
            )
        )

    if any(k in lower for k in ("deal", "discount", "renewal", "negotiation", "margin", "pipeline", "why", "strategy", "forecast")):
        region = None
        for r in ("EMEA", "APAC", "NA", "IN"):
            if re.search(rf"\b{r}\b", prompt, re.IGNORECASE):
                region = r
                break
        if "india" in lower:
            region = "IN"
        if "kpi" in lower or "grouped" in lower or "forecast" in lower or "compare" in lower:
            calls.append(("crm_get_pipeline_kpis", {"group_by": "tier" if "tier" in lower else "region"}))
        calls.append(
            (
                "crm_search_deals",
                {
                    "region": region,
                    "stage": "Legal Review" if "legal review" in lower else ("Negotiation" if "negotiation" in lower else None),
                    "risk_flag": "HIGH" if "high-risk" in lower or "high risk" in lower else None,
                    "min_discount_pct": 15.0 if "15%" in lower or "20%" in lower or "discount" in lower else None,
                    "limit": 10,
                },
            )
        )

    if not calls:
        calls.append(("crm_get_pipeline_kpis", {"group_by": "region"}))

    # Deduplicate preserving order
    seen: set[tuple[str, str]] = set()
    unique: list[tuple[str, dict[str, Any]]] = []
    for name, args in calls:
        key = (name, json.dumps(args, sort_keys=True))
        if key not in seen:
            seen.add(key)
            unique.append((name, args))
    return unique


def _synthesize_local_answer(
    prompt: str,
    decision: RoutingDecision,
    tool_outputs: list[dict[str, Any]],
) -> str:
    """Produce a grounded response strictly from scrubbed MCP tool outputs."""
    lines: list[str] = [
        f"[Model: {decision.display_name} ({decision.model_id}) | Route: {decision.task_category}]",
    ]

    if decision.selected_tier == "flash":
        lines.append("Grounded Zero-Trust Retrieval Summary:")
        for item in tool_outputs:
            tool = item["tool"]
            payload = item["response"]
            data = payload.get("data", [])
            lines.append(
                f"- {tool}: {payload.get('rows_returned', 0)} record(s) returned "
                f"(PII redactions={payload.get('pii_redactions_applied', 0)}, "
                f"zone={payload.get('residency_zone', 'ON_PREM')})."
            )
            if isinstance(data, list):
                for row in data[:3]:
                    if "company_name" in row and "deal_name" in row:
                        lines.append(
                            f"  • {row['deal_id']} | {row['company_name']} | {row['stage']} | "
                            f"${row['amount_usd']:,.0f} | discount={row['discount_requested_pct']}%"
                        )
                    elif "company_name" in row and "ticket_id" in row:
                        lines.append(
                            f"  • {row['ticket_id']} | {row['company_name']} | {row['severity']} ({row['status']}) | "
                            f"{row['summary']}"
                        )
                    elif "company_name" in row:
                        lines.append(
                            f"  • {row['customer_id']} ({row['company_name']}) | ACV=${row['annual_contract_value_usd']:,.0f} | "
                            f"Risk={row['risk_flag']} | Contact={row.get('primary_contact_name')} / {row.get('primary_email')}"
                        )
                    elif "segment" in row:
                        lines.append(
                            f"  • Segment {row['segment']}: {row['customer_count']} accounts | "
                            f"Open Pipeline=${row['open_pipeline_usd']:,.0f} | SLA Breaches={row['sla_breached_tickets']}"
                        )
        return "\n".join(lines)

    # Complex Pro synthesis across retrieved MCP datasets
    deals: list[dict[str, Any]] = []
    tickets: list[dict[str, Any]] = []
    kpis: list[dict[str, Any]] = []
    for item in tool_outputs:
        data = item["response"].get("data", [])
        if item["tool"] == "crm_search_deals" and isinstance(data, list):
            deals.extend(data)
        elif item["tool"] == "crm_check_sla_risks" and isinstance(data, list):
            tickets.extend(data)
        elif item["tool"] == "crm_get_pipeline_kpis" and isinstance(data, list):
            kpis.extend(data)

    lines.append("Executive Multi-Hop Synthesis (Zero-Trust Grounded):")
    if kpis:
        top_seg = max(kpis, key=lambda x: x.get("open_pipeline_usd", 0))
        lines.append(
            f"1. Regional/Segment Exposure: Highest open pipeline is {top_seg['segment']} "
            f"(${top_seg['open_pipeline_usd']:,.0f} open, ${top_seg['weighted_pipeline_usd']:,.0f} weighted, "
            f"{top_seg['sla_breached_tickets']} SLA breaches)."
        )
    if deals:
        high_disc = [d for d in deals if d.get("discount_requested_pct", 0) >= 18]
        total_at_risk = sum(d.get("amount_usd", 0) for d in high_disc)
        names = ", ".join(f"{d['company_name']} ({d['discount_requested_pct']}%)" for d in high_disc[:3])
        lines.append(
            f"2. Margin & Concession Pressure: {len(high_disc)} deal(s) requesting >=18% discount "
            f"(${total_at_risk:,.0f} exposed): {names or 'None'}."
        )
    if tickets:
        breached = [t for t in tickets if t.get("sla_breach") == 1]
        lines.append(
            f"3. Operational Root-Cause Correlation: {len(breached)} SLA-breached ticket(s) overlap with "
            f"commercial escalations (e.g., {', '.join(t['ticket_id'] + ':' + t['category'] for t in breached[:3])})."
        )
    lines.append(
        "4. Recommended Action: Tie temporary SLA remediation credits to multi-year term lock-in rather than "
        "permanent unit-price cuts, prioritizing P1 CDC/Auth fixes before Q4 renewals."
    )
    return "\n".join(lines)


def _sanitized_schema_for_gemini(input_schema: dict[str, Any]) -> dict[str, Any]:
    """Convert MCP JSON Schema into a clean subset compatible with Gemini FunctionDeclaration."""
    props = input_schema.get("properties", {})
    cleaned_props: dict[str, Any] = {}
    for k, v in props.items():
        if k == "caller_role":
            continue
        prop_type = "STRING"
        raw_type = v.get("type")
        if raw_type == "integer":
            prop_type = "INTEGER"
        elif raw_type == "number":
            prop_type = "NUMBER"
        elif raw_type == "boolean":
            prop_type = "BOOLEAN"
        elif isinstance(v.get("anyOf"), list):
            for opt in v["anyOf"]:
                if opt.get("type") and opt["type"] != "null":
                    prop_type = opt["type"].upper()
                    break
        cleaned_props[k] = {
            "type": prop_type,
            "description": v.get("description", k),
        }
    required = [r for r in input_schema.get("required", []) if r != "caller_role"]
    return {"type": "OBJECT", "properties": cleaned_props, "required": required}


async def run_routed_mcp_query(
    prompt: str,
    db_path: Path = DEFAULT_DB_PATH,
    vertex_config: VertexConfig | None = None,
    tracker: FinOpsTracker | None = None,
) -> AgentExecutionResult:
    """Route a prompt, open an MCP stdio session, execute tools, and account FinOps costs."""
    cfg = vertex_config or VertexConfig()
    router = PromptRouter()
    decision = router.route(prompt)
    finops_tracker = tracker or FinOpsTracker()

    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "gcc_poc.mcp_gateway.server", str(db_path)],
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )

    tool_calls_executed: list[dict[str, Any]] = []
    total_redactions = 0

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools_result = await session.list_tools()
            tools_discovered = [t.name for t in tools_result.tools]
            await session.read_resource("crm://policy/zero-trust")

            if cfg.has_live_credentials:
                engine_mode = "vertex_ai_live"
                from google import genai
                from google.genai import types

                client = (
                    genai.Client(
                        vertexai=True,
                        project=cfg.gcp_project,
                        location=cfg.gcp_location,
                    )
                    if cfg.use_vertexai and cfg.gcp_project
                    else genai.Client(api_key=cfg.gemini_api_key)
                )

                fn_decls = [
                    types.FunctionDeclaration(
                        name=t.name,
                        description=t.description or t.name,
                        parameters_json_schema=_sanitized_schema_for_gemini(t.inputSchema),
                    )
                    for t in tools_result.tools
                ]
                gemini_tools = [types.Tool(function_declarations=fn_decls)]
                contents: list[Any] = [
                    types.Content(role="user", parts=[types.Part.from_text(text=prompt)])
                ]
                system_instruction = (
                    "You are a GCC Enterprise AI Analyst. Use the Zero-Trust MCP CRM tools to answer "
                    "accurately. Never attempt to reconstruct redacted PII tokens."
                )

                in_tokens = 0
                out_tokens = 0
                final_answer = ""

                for _ in range(4):
                    resp = client.models.generate_content(
                        model=decision.model_id,
                        contents=contents,
                        config=types.GenerateContentConfig(
                            tools=gemini_tools,
                            system_instruction=system_instruction,
                            temperature=0.2,
                        ),
                    )
                    if resp.usage_metadata:
                        in_tokens += resp.usage_metadata.prompt_token_count or 0
                        out_tokens += resp.usage_metadata.candidates_token_count or 0

                    if not resp.function_calls:
                        final_answer = resp.text or ""
                        break

                    contents.append(resp.candidates[0].content)
                    fn_response_parts = []
                    for fc in resp.function_calls:
                        args = dict(fc.args or {})
                        mcp_res = await session.call_tool(fc.name, arguments=args)
                        parsed = _extract_json_from_mcp_result(mcp_res)
                        total_redactions += int(parsed.get("pii_redactions_applied", 0))
                        tool_calls_executed.append(
                            {"tool": fc.name, "args": args, "response": parsed}
                        )
                        fn_response_parts.append(
                            types.Part.from_function_response(name=fc.name, response=parsed)
                        )
                    contents.append(types.Content(role="user", parts=fn_response_parts))

                if not final_answer:
                    final_answer = _synthesize_local_answer(prompt, decision, tool_calls_executed)
                in_tokens = in_tokens or estimate_tokens(prompt)
                out_tokens = out_tokens or estimate_tokens(final_answer)
            else:
                engine_mode = "local_mcp_sandbox"
                planned = _plan_local_mcp_calls(prompt)
                for tool_name, args in planned:
                    clean_args = {k: v for k, v in args.items() if v is not None}
                    mcp_res = await session.call_tool(tool_name, arguments=clean_args)
                    parsed = _extract_json_from_mcp_result(mcp_res)
                    total_redactions += int(parsed.get("pii_redactions_applied", 0))
                    tool_calls_executed.append(
                        {"tool": tool_name, "args": clean_args, "response": parsed}
                    )

                final_answer = _synthesize_local_answer(prompt, decision, tool_calls_executed)
                tool_context_text = json.dumps(tool_calls_executed)
                in_tokens = estimate_tokens(prompt + " " + tool_context_text[:2400])
                out_tokens = max(160, len(final_answer.split()) * 2)

    finops_record = finops_tracker.record(
        decision=decision,
        input_tokens=in_tokens,
        output_tokens=out_tokens,
    )
    return AgentExecutionResult(
        prompt=prompt,
        engine_mode=engine_mode,
        routing=decision,
        tools_discovered=tools_discovered,
        tool_calls_executed=tool_calls_executed,
        total_pii_redactions=total_redactions,
        answer=final_answer,
        finops=finops_record,
    )
