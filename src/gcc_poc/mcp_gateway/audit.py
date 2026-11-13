"""Immutable Zero-Trust audit trail logger (SQLite + append-only JSONL)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import DEFAULT_AUDIT_LOG_PATH, DEFAULT_DB_PATH, ZeroTrustConfig
from ..crm_db import get_connection


class AuditLogger:
    """Records every MCP tool call (ALLOW or DENY) with redaction & digest metadata."""

    def __init__(
        self,
        db_path: Path = DEFAULT_DB_PATH,
        jsonl_path: Path = DEFAULT_AUDIT_LOG_PATH,
        config: ZeroTrustConfig | None = None,
    ) -> None:
        self.db_path = db_path
        self.jsonl_path = jsonl_path
        self.config = config or ZeroTrustConfig()

    def record(
        self,
        *,
        caller_role: str,
        tool_name: str,
        sanitized_args: dict[str, Any],
        decision: str,
        rows_returned: int,
        pii_redactions: int,
        payload_sha256: str,
    ) -> dict[str, Any]:
        timestamp = datetime.now(timezone.utc).isoformat()
        args_json = json.dumps(sanitized_args, sort_keys=True, default=str)

        entry = {
            "timestamp_utc": timestamp,
            "caller_role": caller_role,
            "tool_name": tool_name,
            "sanitized_args": sanitized_args,
            "decision": decision,
            "rows_returned": rows_returned,
            "pii_redactions": pii_redactions,
            "payload_sha256": payload_sha256,
            "residency_zone": self.config.data_residency_zone,
        }

        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        with self.jsonl_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        conn = get_connection(self.db_path)
        try:
            conn.execute(
                """
                INSERT INTO audit_log (
                    timestamp_utc, caller_role, tool_name, sanitized_args,
                    decision, rows_returned, pii_redactions, payload_sha256, residency_zone
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    caller_role,
                    tool_name,
                    args_json,
                    decision,
                    rows_returned,
                    pii_redactions,
                    payload_sha256,
                    self.config.data_residency_zone,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        return entry

    def recent_entries(self, limit: int = 20) -> list[dict[str, Any]]:
        conn = get_connection(self.db_path)
        try:
            rows = conn.execute(
                """
                SELECT audit_id, timestamp_utc, caller_role, tool_name, sanitized_args,
                       decision, rows_returned, pii_redactions, payload_sha256, residency_zone
                FROM audit_log
                ORDER BY audit_id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

