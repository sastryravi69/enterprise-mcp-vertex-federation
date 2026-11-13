"""In-transit PII tokenization, secret redaction, and payload digest verification."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from typing import Any

# Patterns tuned for enterprise CRM PII and leaked operational secrets
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(
    r"(?<!\w)(?:\+\d{1,3}[-.\s]?(?:\(?\d{2,5}\)?[-.\s]?){1,3}\d{3,10}"
    r"|\(\d{3}\)[-.\s]?\d{3}[-.\s]?\d{4}"
    r"|\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b"
    r"|\b\d{5}[-.\s]\d{5}\b)(?!\w)"
)
PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
TAX_ID_RE = re.compile(r"\b(?:EIN|DE|GB|SE|SG|TW)-[A-Z0-9-]{6,18}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
API_KEY_RE = re.compile(r"\b(?:sk|pk|rk)-(?:live|test|proj)?-?[A-Za-z0-9_-]{8,}\b")
PRIVATE_IP_RE = re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")


class PrivacyScrubber:
    """Scrubs PII and secrets before any CRM payload leaves the MCP boundary."""

    def __init__(self, strict: bool = True, salt: str | None = None) -> None:
        self.strict = strict
        self._salt = (salt or os.getenv("GCC_POC_TOKEN_SALT", "gcc-zero-trust-enclave-salt")).encode("utf-8")

    def tokenize(self, value: str, prefix: str) -> str:
        """Return a deterministic pseudonymous token so agents can correlate without raw PII."""
        digest = hmac.new(self._salt, value.strip().lower().encode("utf-8"), hashlib.sha256).hexdigest()[:6]
        return f"[{prefix}_TOKEN_{digest}]"

    def scrub_text(self, text: str, known_names: list[str] | None = None) -> tuple[str, int]:
        """Redact emails, phones, tax IDs, secrets, private IPs, and known contact names."""
        if not text:
            return text, 0

        redactions = 0
        scrubbed = text

        def _replace_email(match: re.Match[str]) -> str:
            nonlocal redactions
            redactions += 1
            return self.tokenize(match.group(0), "EMAIL")

        scrubbed = EMAIL_RE.sub(_replace_email, scrubbed)

        for pattern, replacement in (
            (API_KEY_RE, "[SECRET_REDACTED]"),
            (PAN_RE, "[TAX_ID_REDACTED]"),
            (TAX_ID_RE, "[TAX_ID_REDACTED]"),
            (SSN_RE, "[SSN_REDACTED]"),
            (PHONE_RE, "[PHONE_REDACTED]"),
            (PRIVATE_IP_RE, "[INTERNAL_IP_REDACTED]"),
        ):
            scrubbed, count = pattern.subn(replacement, scrubbed)
            redactions += count

        if self.strict and known_names:
            for name in known_names:
                clean = name.strip()
                if clean and len(clean) >= 3:
                    name_pattern = re.compile(rf"\b{re.escape(clean)}\b", flags=re.IGNORECASE)
                    if name_pattern.search(scrubbed):
                        token = self.tokenize(clean, "CONTACT")
                        scrubbed, count = name_pattern.subn(token, scrubbed)
                        redactions += count

        return scrubbed, redactions

    def sanitize_record(
        self,
        record: dict[str, Any],
        blocked_columns: frozenset[str],
        pii_token_columns: frozenset[str] = frozenset({"primary_contact_name", "primary_email"}),
        pii_redact_columns: frozenset[str] = frozenset({"primary_phone"}),
        known_names: list[str] | None = None,
    ) -> tuple[dict[str, Any], int]:
        """Remove blocked columns and tokenize/scrub remaining fields."""
        sanitized: dict[str, Any] = {}
        redactions = 0

        for key, value in record.items():
            if key in blocked_columns:
                redactions += 1
                continue

            if value is None:
                sanitized[key] = None
                continue

            if key in pii_token_columns and isinstance(value, str):
                prefix = "EMAIL" if "email" in key else "CONTACT"
                sanitized[key] = self.tokenize(value, prefix) if self.strict else value
                if self.strict:
                    redactions += 1
            elif key in pii_redact_columns and isinstance(value, str):
                sanitized[key] = "[PHONE_REDACTED]" if self.strict else value
                if self.strict:
                    redactions += 1
            elif isinstance(value, str):
                clean_val, count = self.scrub_text(value, known_names=known_names)
                sanitized[key] = clean_val
                redactions += count
            else:
                sanitized[key] = value

        return sanitized, redactions


def compute_payload_sha256(payload: Any) -> str:
    """Compute a stable SHA-256 digest of the sanitized response crossing the boundary."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

