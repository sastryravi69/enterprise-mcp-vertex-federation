"""Python-based Zero-Trust Model Context Protocol (MCP) Server.

Sits between the local mock on-prem Legacy CRM (SQLite) and Vertex AI / Agentforce.
Guarantees:
1. Data never leaves the enclave in bulk or raw PII form (compute-to-data + tokenization).
2. No raw SQL execution; only strictly typed, parameterized tools.
3. Every crossing is ABAC-checked, PII-scrubbed, hashed, and logged.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from mcp.server import MCPServer

from ..config import DEFAULT_AUDIT_LOG_PATH, DEFAULT_DB_PATH, ZeroTrustConfig
from ..crm_db import get_connection, init_database
from .audit import AuditLogger
from .policy import PolicyViolationError, ZeroTrustPolicyEngine
from .privacy import PrivacyScrubber, compute_payload_sha256


class CrmGatewayService:
    """Core Zero-Trust gateway logic shared by MCP tools and local verification."""

    def __init__(
        self,
        db_path: Path = DEFAULT_DB_PATH,
        audit_path: Path = DEFAULT_AUDIT_LOG_PATH,
        config: ZeroTrustConfig | None = None,
    ) -> None:
        self.db_path = db_path
        self.config = config or ZeroTrustConfig()
        init_database(self.db_path)
        self.policy = ZeroTrustPolicyEngine(self.config)
        self.scrubber = PrivacyScrubber(strict=self.config.strict_pii_masking)
        self.audit = AuditLogger(db_path=self.db_path, jsonl_path=audit_path, config=self.config)

    def _known_contact_names(self) -> list[str]:
        conn = get_connection(self.db_path)
        try:
            rows = conn.execute("SELECT primary_contact_name FROM customers").fetchall()
            return [r["primary_contact_name"] for r in rows]
        finally:
            conn.close()

    def _audit_and_wrap(
        self,
        *,
        caller_role: str,
        tool_name: str,
        args: dict[str, Any],
        records: list[dict[str, Any]] | dict[str, Any],
        redactions: int,
        rows_returned: int,
    ) -> dict[str, Any]:
        payload = {
            "residency_zone": self.config.data_residency_zone,
            "zero_trust_enforced": True,
            "pii_redactions_applied": redactions,
            "rows_returned": rows_returned,
            "data": records,
        }
        digest = compute_payload_sha256(payload)
        payload["payload_sha256"] = digest
        self.audit.record(
            caller_role=caller_role,
            tool_name=tool_name,
            sanitized_args=args,
            decision="ALLOW",
            rows_returned=rows_returned,
            pii_redactions=redactions,
            payload_sha256=digest,
        )
        return payload

    def _deny_and_raise(
        self, *, caller_role: str, tool_name: str, args: dict[str, Any], err: PolicyViolationError
    ) -> None:
        digest = compute_payload_sha256({"error": str(err)})
        self.audit.record(
            caller_role=caller_role,
            tool_name=tool_name,
            sanitized_args=args,
            decision=f"DENY: {err}",
            rows_returned=0,
            pii_redactions=0,
            payload_sha256=digest,
        )
        raise err

    def get_account_summary(
        self, customer_query: str, caller_role: str = "vertex_agent"
    ) -> dict[str, Any]:
        args = {"customer_query": customer_query}
        try:
            decision = self.policy.authorize_tool(
                "crm_get_account_summary", caller_role=caller_role, requested_limit=5, args=args
            )
        except PolicyViolationError as exc:
            self._deny_and_raise(
                caller_role=caller_role, tool_name="crm_get_account_summary", args=args, err=exc
            )

        q = customer_query.strip()
        like_q = f"%{q}%"
        known_names = self._known_contact_names()
        conn = get_connection(self.db_path)
        try:
            customers = conn.execute(
                """
                SELECT customer_id, company_name, industry, tier, region,
                       pan_or_tax_id, primary_contact_name, primary_email, primary_phone,
                       annual_contract_value_usd, account_owner, risk_flag, renewal_date
                FROM customers
                WHERE UPPER(customer_id) = UPPER(?) OR LOWER(company_name) LIKE LOWER(?)
                ORDER BY annual_contract_value_usd DESC
                LIMIT ?
                """,
                (q, like_q, decision.effective_limit),
            ).fetchall()

            results: list[dict[str, Any]] = []
            total_redactions = 0

            for cust_row in customers:
                cust_dict = dict(cust_row)
                scrubbed_cust, r_count = self.scrubber.sanitize_record(
                    cust_dict,
                    blocked_columns=self.config.blocked_columns,
                    known_names=known_names,
                )
                total_redactions += r_count

                deal_agg = conn.execute(
                    """
                    SELECT COUNT(*) AS deal_count,
                           COALESCE(SUM(amount_usd), 0) AS open_pipeline_usd,
                           COALESCE(MAX(discount_requested_pct), 0) AS max_discount_requested_pct
                    FROM deals
                    WHERE customer_id = ? AND stage NOT IN ('Closed Won', 'Closed Lost')
                    """,
                    (cust_dict["customer_id"],),
                ).fetchone()

                ticket_agg = conn.execute(
                    """
                    SELECT COUNT(*) AS open_tickets,
                           COALESCE(SUM(CASE WHEN severity = 'P1' AND status != 'Resolved' THEN 1 ELSE 0 END), 0) AS open_p1_tickets,
                           COALESCE(SUM(sla_breach), 0) AS total_sla_breaches
                    FROM support_tickets
                    WHERE customer_id = ?
                    """,
                    (cust_dict["customer_id"],),
                ).fetchone()

                scrubbed_cust["deal_metrics"] = dict(deal_agg)
                scrubbed_cust["support_metrics"] = dict(ticket_agg)
                results.append(scrubbed_cust)

            return self._audit_and_wrap(
                caller_role=decision.caller_role,
                tool_name="crm_get_account_summary",
                args=args,
                records=results,
                redactions=total_redactions,
                rows_returned=len(results),
            )
        finally:
            conn.close()

    def search_deals(
        self,
        region: str | None = None,
        stage: str | None = None,
        risk_flag: str | None = None,
        min_discount_pct: float | None = None,
        limit: int = 10,
        caller_role: str = "vertex_agent",
    ) -> dict[str, Any]:
        args = {
            "region": region,
            "stage": stage,
            "risk_flag": risk_flag,
            "min_discount_pct": min_discount_pct,
            "limit": limit,
        }
        try:
            decision = self.policy.authorize_tool(
                "crm_search_deals", caller_role=caller_role, requested_limit=limit, args=args
            )
        except PolicyViolationError as exc:
            self._deny_and_raise(
                caller_role=caller_role, tool_name="crm_search_deals", args=args, err=exc
            )

        clauses = ["1=1"]
        params: list[Any] = []
        if region:
            clauses.append("UPPER(c.region) = UPPER(?)")
            params.append(region.strip())
        if stage:
            clauses.append("LOWER(d.stage) = LOWER(?)")
            params.append(stage.strip())
        if risk_flag:
            clauses.append("UPPER(c.risk_flag) = UPPER(?)")
            params.append(risk_flag.strip())
        if min_discount_pct is not None:
            clauses.append("d.discount_requested_pct >= ?")
            params.append(float(min_discount_pct))

        params.append(decision.effective_limit)
        sql = f"""
            SELECT d.deal_id, d.customer_id, c.company_name, c.region, c.tier, c.risk_flag,
                   c.annual_contract_value_usd, d.deal_name, d.stage, d.amount_usd,
                   d.probability, d.expected_close_date, d.discount_requested_pct,
                   d.approval_status, d.competitor
            FROM deals d
            JOIN customers c ON c.customer_id = d.customer_id
            WHERE {' AND '.join(clauses)}
            ORDER BY d.amount_usd DESC
            LIMIT ?
        """

        known_names = self._known_contact_names()
        conn = get_connection(self.db_path)
        try:
            rows = conn.execute(sql, params).fetchall()
            sanitized_rows: list[dict[str, Any]] = []
            total_redactions = 0
            for row in rows:
                clean, r_count = self.scrubber.sanitize_record(
                    dict(row),
                    blocked_columns=self.config.blocked_columns,
                    known_names=known_names,
                )
                total_redactions += r_count
                sanitized_rows.append(clean)

            return self._audit_and_wrap(
                caller_role=decision.caller_role,
                tool_name="crm_search_deals",
                args=args,
                records=sanitized_rows,
                redactions=total_redactions,
                rows_returned=len(sanitized_rows),
            )
        finally:
            conn.close()

    def check_sla_risks(
        self,
        severity: str | None = None,
        region: str | None = None,
        only_sla_breached: bool = False,
        limit: int = 10,
        caller_role: str = "vertex_agent",
    ) -> dict[str, Any]:
        args = {
            "severity": severity,
            "region": region,
            "only_sla_breached": only_sla_breached,
            "limit": limit,
        }
        try:
            decision = self.policy.authorize_tool(
                "crm_check_sla_risks", caller_role=caller_role, requested_limit=limit, args=args
            )
        except PolicyViolationError as exc:
            self._deny_and_raise(
                caller_role=caller_role, tool_name="crm_check_sla_risks", args=args, err=exc
            )

        clauses = ["1=1"]
        params: list[Any] = []
        if severity:
            clauses.append("UPPER(t.severity) = UPPER(?)")
            params.append(severity.strip())
        if region:
            clauses.append("UPPER(c.region) = UPPER(?)")
            params.append(region.strip())
        if only_sla_breached:
            clauses.append("t.sla_breach = 1")

        params.append(decision.effective_limit)
        sql = f"""
            SELECT t.ticket_id, t.customer_id, c.company_name, c.region, c.risk_flag,
                   t.severity, t.status, t.category, t.summary, t.internal_notes,
                   t.sla_breach, t.created_at
            FROM support_tickets t
            JOIN customers c ON c.customer_id = t.customer_id
            WHERE {' AND '.join(clauses)}
            ORDER BY t.sla_breach DESC, t.severity ASC, t.created_at DESC
            LIMIT ?
        """

        known_names = self._known_contact_names()
        conn = get_connection(self.db_path)
        try:
            rows = conn.execute(sql, params).fetchall()
            sanitized_rows: list[dict[str, Any]] = []
            total_redactions = 0
            for row in rows:
                clean, r_count = self.scrubber.sanitize_record(
                    dict(row),
                    blocked_columns=self.config.blocked_columns,
                    known_names=known_names,
                )
                total_redactions += r_count
                sanitized_rows.append(clean)

            return self._audit_and_wrap(
                caller_role=decision.caller_role,
                tool_name="crm_check_sla_risks",
                args=args,
                records=sanitized_rows,
                redactions=total_redactions,
                rows_returned=len(sanitized_rows),
            )
        finally:
            conn.close()

    def get_pipeline_kpis(
        self, group_by: str = "region", caller_role: str = "vertex_agent"
    ) -> dict[str, Any]:
        """Compute-to-Data local aggregation: zero customer PII leaves the DB."""
        allowed_groups = {"region": "c.region", "tier": "c.tier", "risk_flag": "c.risk_flag"}
        group_col = allowed_groups.get(group_by.strip().lower())
        args = {"group_by": group_by}
        try:
            decision = self.policy.authorize_tool(
                "crm_get_pipeline_kpis", caller_role=caller_role, requested_limit=15, args=args
            )
            if not group_col:
                raise PolicyViolationError(
                    f"ZERO_TRUST_DENY: group_by must be one of {sorted(allowed_groups)}."
                )
        except PolicyViolationError as exc:
            self._deny_and_raise(
                caller_role=caller_role, tool_name="crm_get_pipeline_kpis", args=args, err=exc
            )

        sql = f"""
            SELECT {group_col} AS segment,
                   COUNT(DISTINCT c.customer_id) AS customer_count,
                   ROUND(SUM(DISTINCT c.annual_contract_value_usd), 2) AS total_acv_usd,
                   ROUND(COALESCE(SUM(CASE WHEN d.stage NOT IN ('Closed Won', 'Closed Lost') THEN d.amount_usd ELSE 0 END), 0), 2) AS open_pipeline_usd,
                   ROUND(COALESCE(SUM(CASE WHEN d.stage NOT IN ('Closed Won', 'Closed Lost') THEN d.amount_usd * (d.probability / 100.0) ELSE 0 END), 0), 2) AS weighted_pipeline_usd,
                   ROUND(COALESCE(AVG(CASE WHEN d.stage NOT IN ('Closed Won', 'Closed Lost') THEN d.discount_requested_pct END), 0), 2) AS avg_discount_requested_pct,
                   COUNT(DISTINCT CASE WHEN t.sla_breach = 1 THEN t.ticket_id END) AS sla_breached_tickets
            FROM customers c
            LEFT JOIN deals d ON d.customer_id = c.customer_id
            LEFT JOIN support_tickets t ON t.customer_id = c.customer_id
            GROUP BY {group_col}
            ORDER BY open_pipeline_usd DESC
        """
        conn = get_connection(self.db_path)
        try:
            rows = [dict(r) for r in conn.execute(sql).fetchall()]
            return self._audit_and_wrap(
                caller_role=decision.caller_role,
                tool_name="crm_get_pipeline_kpis",
                args=args,
                records=rows,
                redactions=0,
                rows_returned=len(rows),
            )
        finally:
            conn.close()

    def get_audit_trail(
        self, limit: int = 10, caller_role: str = "security_auditor"
    ) -> dict[str, Any]:
        args = {"limit": limit}
        try:
            decision = self.policy.authorize_tool(
                "crm_get_audit_trail", caller_role=caller_role, requested_limit=limit, args=args
            )
        except PolicyViolationError as exc:
            self._deny_and_raise(
                caller_role=caller_role, tool_name="crm_get_audit_trail", args=args, err=exc
            )

        entries = self.audit.recent_entries(limit=decision.effective_limit)
        return self._audit_and_wrap(
            caller_role=decision.caller_role,
            tool_name="crm_get_audit_trail",
            args=args,
            records=entries,
            redactions=0,
            rows_returned=len(entries),
        )

    def get_policy_manifest(self) -> dict[str, Any]:
        return {
            "gateway": "GCC Zero-Trust MCP Gateway",
            "residency_zone": self.config.data_residency_zone,
            "strict_pii_masking": self.config.strict_pii_masking,
            "max_rows_per_call": self.config.max_rows_per_call,
            "allow_raw_sql": self.config.allow_raw_sql,
            "allow_bulk_export": self.config.allow_bulk_export,
            "blocked_columns": sorted(self.config.blocked_columns),
            "allowed_roles": list(self.config.allowed_roles),
        }

    def get_sanitized_schema(self) -> dict[str, Any]:
        return {
            "customers": {
                "visible": ["customer_id", "company_name", "industry", "tier", "region", "annual_contract_value_usd", "account_owner", "risk_flag", "renewal_date"],
                "tokenized": ["primary_contact_name", "primary_email"],
                "redacted": ["primary_phone"],
                "blocked": ["pan_or_tax_id"],
            },
            "deals": {
                "visible": ["deal_id", "customer_id", "deal_name", "stage", "amount_usd", "probability", "expected_close_date", "discount_requested_pct", "approval_status", "competitor"],
            },
            "support_tickets": {
                "visible": ["ticket_id", "customer_id", "severity", "status", "category", "sla_breach", "created_at"],
                "inline_scrubbed": ["summary"],
                "blocked": ["internal_notes"],
            },
        }


def build_mcp_server(
    db_path: Path = DEFAULT_DB_PATH,
    audit_path: Path = DEFAULT_AUDIT_LOG_PATH,
) -> MCPServer:
    """Construct the official MCPServer backed by CrmGatewayService."""
    service = CrmGatewayService(db_path=db_path, audit_path=audit_path)
    mcp = MCPServer("gcc-zero-trust-crm-gateway", log_level="WARNING")

    @mcp.tool()
    def crm_get_account_summary(
        customer_query: str, caller_role: str = "vertex_agent"
    ) -> dict[str, Any]:
        """Retrieve a PII-scrubbed customer account profile with aggregated deal & SLA metrics."""
        return service.get_account_summary(customer_query=customer_query, caller_role=caller_role)

    @mcp.tool()
    def crm_search_deals(
        region: str | None = None,
        stage: str | None = None,
        risk_flag: str | None = None,
        min_discount_pct: float | None = None,
        limit: int = 10,
        caller_role: str = "vertex_agent",
    ) -> dict[str, Any]:
        """Search CRM commercial deals using parameterized filters under anti-exfiltration limits."""
        return service.search_deals(
            region=region,
            stage=stage,
            risk_flag=risk_flag,
            min_discount_pct=min_discount_pct,
            limit=limit,
            caller_role=caller_role,
        )

    @mcp.tool()
    def crm_check_sla_risks(
        severity: str | None = None,
        region: str | None = None,
        only_sla_breached: bool = False,
        limit: int = 10,
        caller_role: str = "vertex_agent",
    ) -> dict[str, Any]:
        """Inspect support ticket SLA breaches with internal notes blocked and inline PII scrubbed."""
        return service.check_sla_risks(
            severity=severity,
            region=region,
            only_sla_breached=only_sla_breached,
            limit=limit,
            caller_role=caller_role,
        )

    @mcp.tool()
    def crm_get_pipeline_kpis(
        group_by: str = "region", caller_role: str = "vertex_agent"
    ) -> dict[str, Any]:
        """Compute regional/tier/risk pipeline & SLA aggregates locally without exporting raw rows."""
        return service.get_pipeline_kpis(group_by=group_by, caller_role=caller_role)

    @mcp.tool()
    def crm_get_audit_trail(
        limit: int = 10, caller_role: str = "security_auditor"
    ) -> dict[str, Any]:
        """View immutable Zero-Trust audit logs with redaction counts and SHA-256 digests."""
        return service.get_audit_trail(limit=limit, caller_role=caller_role)

    @mcp.resource("crm://policy/zero-trust")
    def zero_trust_policy_resource() -> str:
        """Read-only Zero-Trust boundary policy manifest."""
        return json.dumps(service.get_policy_manifest(), indent=2)

    @mcp.resource("crm://schema/sanitized")
    def sanitized_schema_resource() -> str:
        """Logical CRM schema showing blocked, redacted, and tokenized fields."""
        return json.dumps(service.get_sanitized_schema(), indent=2)

    return mcp


def main() -> None:
    db_arg = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_DB_PATH
    server = build_mcp_server(db_path=db_arg)
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
