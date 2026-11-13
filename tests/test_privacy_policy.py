"""Tests for Zero-Trust PII tokenization, secret redaction, ABAC policy, and audit logging."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gcc_poc.crm_db import init_database
from gcc_poc.mcp_gateway.policy import PolicyViolationError
from gcc_poc.mcp_gateway.server import CrmGatewayService


@pytest.fixture()
def gateway(tmp_path: Path) -> CrmGatewayService:
    db_path = tmp_path / "test_crm.db"
    audit_path = tmp_path / "audit.jsonl"
    init_database(db_path, reset=True)
    return CrmGatewayService(db_path=db_path, audit_path=audit_path)


def test_pii_and_secrets_never_leave_gateway(gateway: CrmGatewayService) -> None:
    account = gateway.get_account_summary("BharatFin")
    raw_dump = json.dumps(account)

    assert account["zero_trust_enforced"] is True
    assert account["pii_redactions_applied"] >= 3
    assert len(account["payload_sha256"]) == 64

    # Sensitive fields must NEVER appear
    for secret in ("AAACB1234F", "r.iyer@bharatfin.in", "+91-98201-44120", "Rajeshwari Iyer"):
        assert secret not in raw_dump

    record = account["data"][0]
    assert "pan_or_tax_id" not in record
    assert record["primary_email"].startswith("[EMAIL_TOKEN_")
    assert record["primary_contact_name"].startswith("[CONTACT_TOKEN_")
    assert record["primary_phone"] == "[PHONE_REDACTED]"


def test_unstructured_ticket_scrubbing_and_internal_notes_drop(gateway: CrmGatewayService) -> None:
    tickets = gateway.check_sla_risks(severity="P1", limit=10)
    raw_dump = json.dumps(tickets)

    # internal_notes must be stripped completely
    for row in tickets["data"]:
        assert "internal_notes" not in row

    # Embedded secrets/PII inside summary text must be scrubbed
    for sensitive in (
        "sk-live-9948271625abcdef",
        "10.24.8.19",
        "AAACB1234F",
        "r.iyer@bharatfin.in",
        "Lukas Weber",
        "+49-171-8834201",
        "astrid@nordicfreight.se",
        "s.kulkarni@industelecom.in",
    ):
        assert sensitive not in raw_dump


def test_anti_exfiltration_and_abac_denials_are_audited(gateway: CrmGatewayService) -> None:
    with pytest.raises(PolicyViolationError, match="anti-exfiltration"):
        gateway.search_deals(limit=500)

    with pytest.raises(PolicyViolationError, match="Unknown or untrusted"):
        gateway.get_account_summary("C-101", caller_role="untrusted_public_llm")

    with pytest.raises(PolicyViolationError, match="not authorized"):
        gateway.policy.authorize_tool("crm_raw_sql_query", caller_role="vertex_agent")

    with pytest.raises(PolicyViolationError, match="Suspicious SQL"):
        gateway.get_account_summary("C-101; DROP TABLE customers")

    audit = gateway.get_audit_trail(limit=10, caller_role="security_auditor")
    decisions = [e["decision"] for e in audit["data"]]
    assert any(d.startswith("DENY:") for d in decisions)

