"""Attribute-Based Access Control (ABAC) and anti-exfiltration policy engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..config import ZeroTrustConfig


class PolicyViolationError(PermissionError):
    """Raised when a caller violates Zero-Trust MCP boundary constraints."""


@dataclass(frozen=True)
class PolicyDecision:
    """Structured authorization decision for an MCP tool request."""

    allowed: bool
    reason: str
    effective_limit: int
    caller_role: str


TOOL_ROLE_MATRIX: dict[str, set[str]] = {
    "crm_get_account_summary": {"vertex_agent", "agentforce_bridge", "security_auditor"},
    "crm_search_deals": {"vertex_agent", "agentforce_bridge", "security_auditor"},
    "crm_check_sla_risks": {"vertex_agent", "agentforce_bridge", "security_auditor"},
    "crm_get_pipeline_kpis": {"vertex_agent", "agentforce_bridge", "security_auditor"},
    "crm_get_audit_trail": {"security_auditor", "vertex_agent"},
    # Explicitly forbidden operations exposed only as policy-deny tests/checks
    "crm_raw_sql_query": set(),
    "crm_bulk_export_customers": set(),
}


class ZeroTrustPolicyEngine:
    """Enforces least-privilege, row limits, and no-bulk-export rules."""

    def __init__(self, config: ZeroTrustConfig | None = None) -> None:
        self.config = config or ZeroTrustConfig()

    def authorize_tool(
        self,
        tool_name: str,
        caller_role: str | None = None,
        requested_limit: int | None = None,
        args: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        role = (caller_role or self.config.default_caller_role).strip()
        if role not in self.config.allowed_roles:
            raise PolicyViolationError(
                f"ZERO_TRUST_DENY: Unknown or untrusted caller_role '{role}'."
            )

        allowed_roles_for_tool = TOOL_ROLE_MATRIX.get(tool_name)
        if allowed_roles_for_tool is None:
            raise PolicyViolationError(
                f"ZERO_TRUST_DENY: Unregistered MCP tool '{tool_name}'."
            )

        if role not in allowed_roles_for_tool:
            raise PolicyViolationError(
                f"ZERO_TRUST_DENY: Role '{role}' is not authorized to invoke '{tool_name}'."
            )

        # Enforce anti-exfiltration row ceiling
        limit = self.config.max_rows_per_call if requested_limit is None else int(requested_limit)
        if limit <= 0:
            raise PolicyViolationError("ZERO_TRUST_DENY: limit must be >= 1.")
        if limit > self.config.max_rows_per_call:
            raise PolicyViolationError(
                f"ZERO_TRUST_DENY: Requested limit={limit} exceeds anti-exfiltration cap "
                f"({self.config.max_rows_per_call} rows/call)."
            )

        # Reject SQL injection / wildcards designed for full table dumps
        if args:
            for k, v in args.items():
                if isinstance(v, str) and any(
                    tok in v.lower() for tok in ("; drop ", "union select", "pragma ", "sqlite_master")
                ):
                    raise PolicyViolationError(
                        f"ZERO_TRUST_DENY: Suspicious SQL syntax detected in parameter '{k}'."
                    )

        return PolicyDecision(
            allowed=True,
            reason="Authorized under GCC Zero-Trust least-privilege policy.",
            effective_limit=limit,
            caller_role=role,
        )

