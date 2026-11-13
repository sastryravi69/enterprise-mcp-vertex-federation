"""Local mock Legacy On-Premises CRM database (SQLite).

Simulates an enterprise on-prem CRM containing sensitive PII, tax identifiers,
internal escalation secrets, commercial deals, and SLA ticket data that MUST NOT
leave the sovereign boundary unprotected.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .config import DEFAULT_DB_PATH

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS customers (
    customer_id TEXT PRIMARY KEY,
    company_name TEXT NOT NULL,
    industry TEXT NOT NULL,
    tier TEXT NOT NULL,
    region TEXT NOT NULL,
    pan_or_tax_id TEXT NOT NULL,
    primary_contact_name TEXT NOT NULL,
    primary_email TEXT NOT NULL,
    primary_phone TEXT NOT NULL,
    annual_contract_value_usd REAL NOT NULL,
    account_owner TEXT NOT NULL,
    risk_flag TEXT NOT NULL,
    renewal_date TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS deals (
    deal_id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL,
    deal_name TEXT NOT NULL,
    stage TEXT NOT NULL,
    amount_usd REAL NOT NULL,
    probability INTEGER NOT NULL,
    expected_close_date TEXT NOT NULL,
    discount_requested_pct REAL NOT NULL,
    approval_status TEXT NOT NULL,
    competitor TEXT NOT NULL,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

CREATE TABLE IF NOT EXISTS support_tickets (
    ticket_id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    category TEXT NOT NULL,
    summary TEXT NOT NULL,
    internal_notes TEXT NOT NULL,
    sla_breach INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc TEXT NOT NULL,
    caller_role TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    sanitized_args TEXT NOT NULL,
    decision TEXT NOT NULL,
    rows_returned INTEGER NOT NULL,
    pii_redactions INTEGER NOT NULL,
    payload_sha256 TEXT NOT NULL,
    residency_zone TEXT NOT NULL
);
"""

SEED_CUSTOMERS = [
    ("C-101", "BharatFin Systems Ltd", "BFSI", "Strategic", "IN", "AAACB1234F", "Rajeshwari Iyer", "r.iyer@bharatfin.in", "+91-98201-44120", 1_450_000.0, "Ananya Sharma", "HIGH", "2026-12-31", "2023-04-12"),
    ("C-102", "EuroGrid Energy GmbH", "Energy", "Enterprise", "EMEA", "DE-298471022", "Lukas Weber", "l.weber@eurogrid.de", "+49-171-8834201", 980_000.0, "Marcus Vance", "HIGH", "2026-12-15", "2022-09-01"),
    ("C-103", "Meridian Health Partners", "Healthcare", "Strategic", "NA", "EIN-84-3920184", "Elena Rostova", "elena.rostova@meridianhealth.org", "+1-415-890-3321", 1_820_000.0, "David Chen", "MEDIUM", "2027-02-28", "2024-01-18"),
    ("C-104", "Pacific Aero Manufacturing", "Manufacturing", "Enterprise", "APAC", "SG-201948372K", "Kenji Takahashi", "k.takahashi@pacificaero.sg", "+65-9123-7780", 740_000.0, "Ananya Sharma", "LOW", "2027-05-10", "2024-06-22"),
    ("C-105", "Nordic Freight Logistics", "Logistics", "Enterprise", "EMEA", "SE-5567019921", "Astrid Lindholm", "astrid@nordicfreight.se", "+46-70-441-9920", 610_000.0, "Marcus Vance", "HIGH", "2026-11-30", "2023-11-03"),
    ("C-106", "Deccan Pharma Core", "Life Sciences", "Strategic", "IN", "AABCD8871K", "Vikramaditya Rao", "v.rao@deccanpharma.co.in", "+91-98450-11298", 1_260_000.0, "Priya Nair", "LOW", "2027-03-20", "2023-07-14"),
    ("C-107", "Thames Clearing House", "BFSI", "Strategic", "EMEA", "GB-773819204", "Oliver Sterling", "o.sterling@thamesclearing.co.uk", "+44-7700-900412", 2_100_000.0, "Marcus Vance", "MEDIUM", "2027-01-15", "2022-03-09"),
    ("C-108", "Apex Semiconductor Foundry", "High Tech", "Enterprise", "APAC", "TW-88291034", "Mei-Ling Wu", "ml.wu@apexsemi.tw", "+886-912-334-891", 890_000.0, "David Chen", "LOW", "2027-07-01", "2025-01-11"),
    ("C-109", "Sunbelt Retail Holdings", "Retail", "Growth", "NA", "EIN-91-4402819", "Jordan Blake", "j.blake@sunbeltretail.com", "+1-512-555-0149", 340_000.0, "Priya Nair", "MEDIUM", "2026-12-20", "2024-08-30"),
    ("C-110", "Indus Telecom Infrastructure", "Telecom", "Strategic", "IN", "AAACI5509M", "Suresh Kulkarni", "s.kulkarni@industelecom.in", "+91-99001-77312", 1_550_000.0, "Ananya Sharma", "HIGH", "2026-12-10", "2023-02-19"),
]

SEED_DEALS = [
    ("D-2001", "C-101", "BharatFin Core Treasury AI Expansion", "Negotiation", 620_000.0, 65, "2026-12-20", 18.0, "Pending CFO", "FinCloud AI"),
    ("D-2002", "C-101", "BharatFin Compliance Copilot Renewal", "Legal Review", 1_450_000.0, 75, "2026-12-31", 12.0, "Approved", "Internal Build"),
    ("D-2003", "C-102", "EuroGrid Smart Metering Lakehouse", "Negotiation", 980_000.0, 50, "2026-12-15", 22.0, "Escalated", "SnowLake Corp"),
    ("D-2004", "C-102", "EuroGrid OT Anomaly Module", "Qualification", 410_000.0, 35, "2027-03-15", 10.0, "Draft", "Dataplex"),
    ("D-2005", "C-103", "Meridian HIPAA Zero-Copy Bridge", "Legal Review", 890_000.0, 80, "2026-12-28", 8.0, "Approved", "None"),
    ("D-2006", "C-104", "Pacific Aero Predictive Maintenance", "Closed Won", 740_000.0, 100, "2026-10-15", 5.0, "Approved", "None"),
    ("D-2007", "C-105", "Nordic Freight Customs Automation Renewal", "Negotiation", 610_000.0, 45, "2026-11-30", 25.0, "Rejected - Margin Floor", "LogiMind"),
    ("D-2008", "C-106", "Deccan Pharma R&D RAG Vault", "Closed Won", 540_000.0, 100, "2026-09-30", 6.0, "Approved", "None"),
    ("D-2009", "C-107", "Thames Clearing Real-Time AML Mesh", "Negotiation", 1_300_000.0, 70, "2026-12-22", 14.0, "Pending VP Sales", "FinCloud AI"),
    ("D-2010", "C-107", "Thames Settlement Multi-Region Renewal", "Legal Review", 2_100_000.0, 85, "2027-01-15", 9.0, "Approved", "Internal Build"),
    ("D-2011", "C-108", "Apex Yield Analytics Seat Expansion", "Qualification", 390_000.0, 60, "2027-02-10", 7.0, "Draft", "SnowLake Corp"),
    ("D-2012", "C-109", "Sunbelt Omnichannel Agentforce Sync", "Prospecting", 220_000.0, 30, "2027-03-01", 11.0, "Draft", "Zendata"),
    ("D-2013", "C-110", "Indus NOC Autonomous Triage Renewal", "Negotiation", 1_550_000.0, 55, "2026-12-10", 20.0, "Pending CFO", "TelcoOps AI"),
    ("D-2014", "C-110", "Indus Edge Billing Reconciliation", "Qualification", 480_000.0, 40, "2027-04-05", 15.0, "Draft", "Internal Build"),
    ("D-2015", "C-103", "Meridian Clinical Claims Summarizer", "Closed Won", 460_000.0, 100, "2026-10-28", 4.0, "Approved", "None"),
    ("D-2016", "C-105", "Nordic Cold-Chain Telemetry Connector", "Closed Lost", 320_000.0, 0, "2026-10-05", 15.0, "Closed", "LogiMind"),
]

SEED_TICKETS = [
    ("T-9001", "C-101", "P1", "Escalated", "Data Residency", "Audit alert: outbound payload verification required for RBI compliance; contact r.iyer@bharatfin.in requested trace.", "SECRET_NOTE: Prod Oracle password rotated by Ramesh on 10.24.8.19; PAN AAACB1234F verified.", 1, "2026-11-08T09:15:00Z"),
    ("T-9002", "C-101", "P2", "Open", "Latency", "Batch sync from Tally XML connector spiking above 45s during market close.", "DBA ticket #4412 assigned to Bangalore NOC; call +91-98201-44120 after patch.", 0, "2026-11-09T14:20:00Z"),
    ("T-9003", "C-102", "P1", "Escalated", "Connector Failure", "Oracle CDC GoldenGate lag > 4 hours affecting EMEA billing dashboard; Lukas Weber (+49-171-8834201) escalated to VP.", "Internal escalation: customer threatening non-renewal of $980k deal D-2003 unless SLA credit issued.", 1, "2026-11-07T07:45:00Z"),
    ("T-9004", "C-102", "P1", "Open", "Auth Token", "Workload Identity OIDC token refresh failed intermittently on Frankfurt private endpoint.", "Vault token lease TTL misconfigured at 15m; key alias DE-298471022.", 1, "2026-11-10T11:10:00Z"),
    ("T-9005", "C-103", "P2", "Resolved", "Masking Policy", "HIPAA SSN pattern check requested on clinical notes export pipeline.", "Verified zero raw PHI leaves enclave.", 0, "2026-11-01T16:00:00Z"),
    ("T-9006", "C-105", "P1", "Escalated", "SLA Breach", "Customs webhook timeout for Nordic Freight; email astrid@nordicfreight.se copied on incident bridge.", "Customer demanding 25% discount on D-2007 due to 3 SLA breaches this quarter.", 1, "2026-11-06T06:30:00Z"),
    ("T-9007", "C-105", "P2", "Open", "Data Drift", "Schema mismatch on legacy EDI freight manifest ingestion.", "Pending mapping patch in Unity Catalog silver table.", 0, "2026-11-09T10:05:00Z"),
    ("T-9008", "C-107", "P1", "Open", "Compliance", "FCA audit trail export verification for Thames Clearing settlement jobs.", "API key sk-live-9948271625abcdef leaked in legacy log file - purged & rotated!", 1, "2026-11-10T08:50:00Z"),
    ("T-9009", "C-107", "P3", "Resolved", "UI Latency", "Agentforce sidebar slow loading historical deal summaries.", "Resolved via Flash router tiering.", 0, "2026-11-03T12:12:00Z"),
    ("T-9010", "C-110", "P1", "Escalated", "Outage", "On-prem CRM connector thread pool exhaustion during Mumbai peak traffic; s.kulkarni@industelecom.in requested RCA.", "Internal: Legacy DB connection pool capped at 32; Tax ID AAACI5509M.", 1, "2026-11-10T17:40:00Z"),
    ("T-9011", "C-110", "P2", "Open", "Alert Noise", "False positive anomaly alerts from regional edge collectors.", "Tuning threshold from 2.0 to 2.5 sigma.", 0, "2026-11-11T04:15:00Z"),
    ("T-9012", "C-104", "P3", "Resolved", "Onboarding", "Additional read-only role requested for Singapore plant analysts.", "Granted via ABAC policy.", 0, "2026-10-29T05:00:00Z"),
    ("T-9013", "C-106", "P3", "Resolved", "Report Export", "Scheduled weekly summary digest formatting issue.", "Fixed template.", 0, "2026-11-02T09:30:00Z"),
    ("T-9014", "C-108", "P2", "Open", "Query Quota", "Spark Delta Sharing concurrent reader limit hit during fab shift handover.", "Increasing Databricks serverless warehouse max clusters.", 0, "2026-11-10T02:20:00Z"),
    ("T-9015", "C-109", "P2", "Open", "Sync Delay", "Salesforce Agentforce action latency spike on inventory lookup.", "Investigating Private Connect route.", 0, "2026-11-09T19:00:00Z"),
    ("T-9016", "C-102", "P2", "Open", "Billing", "Invoice discrepancy on German VAT tax code DE-298471022 reported by Finance.", "Finance ticket #8812.", 0, "2026-11-08T15:10:00Z"),
]


def get_connection(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open a SQLite connection with row dictionary access."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_database(db_path: Path = DEFAULT_DB_PATH, reset: bool = False) -> Path:
    """Create and seed the local mock Legacy On-Premises CRM database."""
    if reset and db_path.exists():
        db_path.unlink()

    conn = get_connection(db_path)
    try:
        conn.executescript(SCHEMA_SQL)
        existing = conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0]
        if existing == 0:
            conn.executemany(
                """
                INSERT INTO customers (
                    customer_id, company_name, industry, tier, region,
                    pan_or_tax_id, primary_contact_name, primary_email,
                    primary_phone, annual_contract_value_usd, account_owner,
                    risk_flag, renewal_date, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                SEED_CUSTOMERS,
            )
            conn.executemany(
                """
                INSERT INTO deals (
                    deal_id, customer_id, deal_name, stage, amount_usd,
                    probability, expected_close_date, discount_requested_pct,
                    approval_status, competitor
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                SEED_DEALS,
            )
            conn.executemany(
                """
                INSERT INTO support_tickets (
                    ticket_id, customer_id, severity, status, category,
                    summary, internal_notes, sla_breach, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                SEED_TICKETS,
            )
            conn.commit()
    finally:
        conn.close()
    return db_path

