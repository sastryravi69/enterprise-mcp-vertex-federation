"""Generates and validates the Hybrid Edge-to-Cloud Architecture Blueprint.

Outputs:
1. architecture/hybrid_edge_to_cloud_blueprint.drawio (Native Draw.io mxfile XML)
2. architecture/hybrid_edge_to_cloud_blueprint.svg (Vector SVG preview)

Also runs geometric overlap validation on sibling components and XML integrity checks.
"""

from __future__ import annotations

import html
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
ARCH_DIR = ROOT_DIR / "architecture"
DRAWIO_PATH = ARCH_DIR / "hybrid_edge_to_cloud_blueprint.drawio"
SVG_PATH = ARCH_DIR / "hybrid_edge_to_cloud_blueprint.svg"


@dataclass
class Box:
    id: str
    label: str
    x: int
    y: int
    w: int
    h: int
    fill: str
    stroke: str
    font_color: str = "#0f172a"
    dashed: bool = False
    rounded: bool = True
    is_container: bool = False
    is_db: bool = False
    font_size: int = 11
    bold: bool = False
    sublabel: str = ""
    parent: str = "1"

    def drawio_label(self) -> str:
        title = f"<b>{html.escape(self.label)}</b>" if self.bold else html.escape(self.label)
        if self.sublabel:
            sub = html.escape(self.sublabel).replace("\n", "<br/>")
            return f"{title}<br/><font style='font-size:10px;color:#334155'>{sub}</font>"
        return title

    def drawio_style(self) -> str:
        parts = [
            "shape=cylinder3;whiteSpace=wrap;html=1;boundedLbl=1;backgroundOutline=1;size=12;"
            if self.is_db
            else f"rounded={'1' if self.rounded else '0'};whiteSpace=wrap;html=1;",
            f"fillColor={self.fill};",
            f"strokeColor={self.stroke};",
            f"fontColor={self.font_color};",
            f"fontSize={self.font_size};",
            "strokeWidth=2;" if self.is_container or self.bold else "strokeWidth=1.5;",
        ]
        if self.dashed:
            parts.append("dashed=1;dashPattern=6 4;")
        if self.is_container:
            parts.append("verticalAlign=top;align=left;spacingLeft=12;spacingTop=8;container=0;")
        else:
            parts.append("verticalAlign=middle;align=center;spacing=6;")
        return "".join(parts)


@dataclass
class Edge:
    id: str
    source: str
    target: str
    label: str
    stroke: str
    dashed: bool = False
    bidirectional: bool = False
    exit_x: float = 1.0
    exit_y: float = 0.5
    entry_x: float = 0.0
    entry_y: float = 0.5
    waypoints: tuple[tuple[int, int], ...] = ()

    def drawio_style(self) -> str:
        parts = [
            "edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;jettySize=auto;html=1;",
            f"strokeColor={self.stroke};",
            "strokeWidth=2.2;",
            f"fontColor={self.stroke};",
            "fontSize=10;fontStyle=1;labelBackgroundColor=#ffffff;",
            f"exitX={self.exit_x};exitY={self.exit_y};exitDx=0;exitDy=0;",
            f"entryX={self.entry_x};entryY={self.entry_y};entryDx=0;entryDy=0;",
        ]
        if self.dashed:
            parts.append("dashed=1;dashPattern=6 4;")
        if self.bidirectional:
            parts.append("startArrow=classic;startFill=1;endArrow=classic;endFill=1;")
        else:
            parts.append("endArrow=classic;endFill=1;")
        return "".join(parts)


def build_diagram_elements() -> tuple[list[Box], list[Edge]]:
    boxes: list[Box] = [
        # Banner
        Box(
            id="banner",
            label="Hybrid Edge-to-Cloud Zero-Trust Agentic AI Blueprint (GCC Reference Architecture)",
            sublabel="Legacy On-Premises (Oracle / CRM)  ->  Azure Databricks (Zero-Copy Layer)  ->  GCP Vertex AI & Salesforce Agentforce",
            x=24,
            y=16,
            w=1772,
            h=58,
            fill="#0f172a",
            stroke="#1e293b",
            font_color="#f8fafc",
            font_size=15,
            bold=True,
        ),
        # Cross-cutting Identity & Governance Fabric
        Box(
            id="fabric_bg",
            label="Cross-Cutting Zero-Trust Identity, Encryption & Governance Fabric",
            x=24,
            y=86,
            w=1772,
            h=86,
            fill="#f8fafc",
            stroke="#64748b",
            dashed=True,
            is_container=True,
            font_size=11,
            bold=True,
        ),
        Box(
            id="iam_oidc",
            label="Entra ID & Workload Identity Federation",
            sublabel="OIDC Short-Lived Tokens | Zero Static API Keys | mTLS 1.3",
            x=44,
            y=116,
            w=540,
            h=46,
            fill="#e2e8f0",
            stroke="#475569",
            bold=True,
        ),
        Box(
            id="kms_cmek",
            label="Customer-Managed Keys (CMEK / BYOK)",
            sublabel="Azure Key Vault HSM + GCP Cloud KMS | Sovereign Key Control",
            x=614,
            y=116,
            w=560,
            h=46,
            fill="#e2e8f0",
            stroke="#475569",
            bold=True,
        ),
        Box(
            id="siem_audit",
            label="Immutable Compliance & FinOps Observability",
            sublabel="SHA-256 MCP Audit Trail | RBI / GDPR / HIPAA / FCA Controls | Cost Ledger",
            x=1204,
            y=116,
            w=572,
            h=46,
            fill="#e2e8f0",
            stroke="#475569",
            bold=True,
        ),
        # ZONE 1: ON-PREM / EDGE
        Box(
            id="zone_edge",
            label="ZONE 1: On-Premises / GCC Sovereign Enclave (Raw PII Never Leaves Boundary)",
            x=24,
            y=190,
            w=416,
            h=770,
            fill="#fff5f5",
            stroke="#dc2626",
            dashed=True,
            is_container=True,
            font_color="#991b1b",
            font_size=12,
            bold=True,
        ),
        Box(
            id="oracle_db",
            label="Oracle DB 19c / 23ai",
            sublabel="GoldenGate / LogMiner CDC\nCore ERP & Financials",
            x=44,
            y=236,
            w=376,
            h=92,
            fill="#fee2e2",
            stroke="#b91c1c",
            is_db=True,
            bold=True,
        ),
        Box(
            id="edge_cdc",
            label="Azure Arc + Self-Hosted IR / CDC Agent",
            sublabel="Outbound Encrypted Delta Stream | Zero Inbound Firewall Ports\nFeeds Schema Metadata & Masked CDC Events to Azure",
            x=44,
            y=352,
            w=376,
            h=78,
            fill="#fef3c7",
            stroke="#d97706",
            bold=True,
        ),
        Box(
            id="legacy_crm",
            label="Legacy On-Prem CRM (Mock PoC DB)",
            sublabel="Customers (PAN/Tax ID, Email, Phone), Deals, Support Tickets + Secrets",
            x=44,
            y=454,
            w=376,
            h=92,
            fill="#fecaca",
            stroke="#991b1b",
            is_db=True,
            bold=True,
        ),
        Box(
            id="mcp_gateway",
            label="Zero-Trust MCP Gateway (Python MCPServer)",
            x=44,
            y=574,
            w=376,
            h=364,
            fill="#ecfdf5",
            stroke="#0f766e",
            is_container=True,
            font_color="#065f46",
            font_size=12,
            bold=True,
        ),
        Box(
            id="mcp_abac",
            label="ABAC Policy & Anti-Exfiltration Engine",
            sublabel="Strict Role Matrix | 15-Row Cap | Raw SQL & Bulk Export DENIED",
            x=64,
            y=616,
            w=336,
            h=64,
            fill="#d1fae5",
            stroke="#047857",
            bold=True,
        ),
        Box(
            id="mcp_privacy",
            label="In-Transit PII Tokenizer & Secret Scrubber",
            sublabel="HMAC Pseudonyms [EMAIL_TOKEN_x] | Redacts PAN, Phone, API Keys",
            x=64,
            y=694,
            w=336,
            h=64,
            fill="#d1fae5",
            stroke="#047857",
            bold=True,
        ),
        Box(
            id="mcp_compute",
            label="Compute-to-Data Tool Registry (stdio / mTLS)",
            sublabel="Local KPI Aggregations (crm_get_pipeline_kpis, crm_check_sla_risks)",
            x=64,
            y=772,
            w=336,
            h=64,
            fill="#d1fae5",
            stroke="#047857",
            bold=True,
        ),
        Box(
            id="mcp_audit",
            label="Immutable SHA-256 Boundary Audit Log",
            sublabel="Records Tool Calls, Redaction Counts & Payload Digests (JSONL + DB)",
            x=64,
            y=850,
            w=336,
            h=64,
            fill="#ccfbf1",
            stroke="#0f766e",
            bold=True,
        ),
        # ZONE 2: AZURE DATABRICKS ZERO-COPY
        Box(
            id="zone_azure",
            label="ZONE 2: Azure Private VNet — Zero-Copy Lakehouse Layer (Azure Databricks)",
            x=472,
            y=190,
            w=468,
            h=770,
            fill="#eff6ff",
            stroke="#1d4ed8",
            dashed=True,
            is_container=True,
            font_color="#1e3a8a",
            font_size=12,
            bold=True,
        ),
        Box(
            id="priv_link_edge",
            label="ExpressRoute / Azure Private Link",
            sublabel="IPsec + mTLS 1.3 Tunnel (No Public Internet Traversal)",
            x=492,
            y=236,
            w=428,
            h=54,
            fill="#dbeafe",
            stroke="#2563eb",
            bold=True,
        ),
        Box(
            id="adls_medallion",
            label="ADLS Gen2 Delta Lake (CMEK Encrypted)",
            sublabel="Bronze (CDC Masked) -> Silver (Conformed) -> Gold (Curated AI Views)",
            x=492,
            y=312,
            w=428,
            h=102,
            fill="#bfdbfe",
            stroke="#1d4ed8",
            is_db=True,
            bold=True,
        ),
        Box(
            id="unity_catalog",
            label="Azure Databricks Unity Catalog (Zero-Copy Governance)",
            x=492,
            y=438,
            w=428,
            h=310,
            fill="#e0f2fe",
            stroke="#0369a1",
            is_container=True,
            font_color="#0c4a6e",
            font_size=11,
            bold=True,
        ),
        Box(
            id="lakehouse_fed",
            label="Lakehouse Federation",
            sublabel="Federated live queries to Oracle metadata without raw data copy",
            x=512,
            y=476,
            w=388,
            h=66,
            fill="#bae6fd",
            stroke="#0284c7",
            bold=True,
        ),
        Box(
            id="rls_masking",
            label="Dynamic Column Masking & Row-Level Security (RLS)",
            sublabel="Blocks Tax/PAN IDs | Enforces Region & Business Unit Isolation",
            x=512,
            y=558,
            w=388,
            h=66,
            fill="#bae6fd",
            stroke="#0284c7",
            bold=True,
        ),
        Box(
            id="delta_sharing",
            label="Delta Sharing & Iceberg Uniform (ZERO-COPY PROTOCOL)",
            sublabel="Shares Gold Views to Vertex AI & Salesforce without ETL Duplication",
            x=512,
            y=640,
            w=388,
            h=84,
            fill="#93c5fd",
            stroke="#1d4ed8",
            bold=True,
        ),
        Box(
            id="databricks_vs",
            label="Databricks Mosaic AI Vector Search & Feature Store",
            sublabel="Pre-Redacted Enterprise Embeddings | Governed by Unity Catalog ACLs",
            x=492,
            y=776,
            w=428,
            h=76,
            fill="#dbeafe",
            stroke="#1e40af",
            bold=True,
        ),
        Box(
            id="zero_copy_badge",
            label="Zero-Copy Guarantee: Single Source of Truth in ADLS/Unity Catalog",
            sublabel="No shadow copies sent to public SaaS or model training buckets",
            x=492,
            y=874,
            w=428,
            h=64,
            fill="#eff6ff",
            stroke="#3b82f6",
            dashed=True,
            bold=True,
        ),
        # ZONE 3: GCP VERTEX AI & FINOPS
        Box(
            id="zone_gcp",
            label="ZONE 3: GCP VPC Service Controls — Vertex AI & FinOps Router",
            x=974,
            y=190,
            w=472,
            h=462,
            fill="#f0fdf4",
            stroke="#15803d",
            dashed=True,
            is_container=True,
            font_color="#14532d",
            font_size=12,
            bold=True,
        ),
        Box(
            id="vpc_sc",
            label="Private Service Connect + Cloud Interconnect (ZDR)",
            sublabel="Zero Data Retention Enabled | CMEK | No Public Egress",
            x=994,
            y=232,
            w=432,
            h=54,
            fill="#dcfce7",
            stroke="#16a34a",
            bold=True,
        ),
        Box(
            id="finops_router",
            label="LLM Routing & FinOps Gateway (Python)",
            sublabel="Pre-Inference Complexity Classifier (<2ms, $0 overhead)",
            x=994,
            y=304,
            w=432,
            h=68,
            fill="#fef9c3",
            stroke="#ca8a04",
            bold=True,
        ),
        Box(
            id="gemini_flash",
            label="Gemini 1.5 Flash (Tier 1)",
            sublabel="85% Traffic | Simple Retrieval & KPIs\n$0.075/1M in | ~420ms (94% cheaper)",
            x=994,
            y=390,
            w=206,
            h=88,
            fill="#dcfce7",
            stroke="#15803d",
            bold=True,
        ),
        Box(
            id="gemini_pro",
            label="Gemini 1.5 Pro (Tier 2)",
            sublabel="15% Traffic | Multi-Hop & Strategy\n$1.25/1M in | ~1850ms",
            x=1220,
            y=390,
            w=206,
            h=88,
            fill="#bbf7d0",
            stroke="#166534",
            bold=True,
        ),
        Box(
            id="vertex_bridge",
            label="Vertex AI Agent Engine & Function-Calling MCP Bridge",
            sublabel="Translates MCP Tools -> Gemini FunctionDeclarations\nConsumes Zero-Copy Gold Views (Delta Sharing / BQ Omni)",
            x=994,
            y=496,
            w=432,
            h=74,
            fill="#d1fae5",
            stroke="#047857",
            bold=True,
        ),
        Box(
            id="finops_ledger",
            label="FinOps Cost & Latency Ledger (66.0% Blended / 94% Flash Savings)",
            sublabel="Per-Query Attribution | Projected ~$15.5k/yr Savings @ 500k q/mo",
            x=994,
            y=584,
            w=432,
            h=52,
            fill="#fef08a",
            stroke="#a16207",
            bold=True,
        ),
        # ZONE 4: SALESFORCE AGENTFORCE
        Box(
            id="zone_sf",
            label="ZONE 4: Salesforce Hyperforce — Agentforce & Trust Layer",
            x=974,
            y=672,
            w=472,
            h=288,
            fill="#ecfeff",
            stroke="#0284c7",
            dashed=True,
            is_container=True,
            font_color="#075985",
            font_size=12,
            bold=True,
        ),
        Box(
            id="sf_data_cloud",
            label="Salesforce Data Cloud (Zero-Copy Federation)",
            sublabel="Reads Databricks Unity Catalog Gold Views via Zero-Copy (No ETL Copy)",
            x=994,
            y=714,
            w=432,
            h=64,
            fill="#cffafe",
            stroke="#0891b2",
            bold=True,
        ),
        Box(
            id="einstein_trust",
            label="Einstein Trust Layer",
            sublabel="Dynamic Grounding | PII Masking | Toxicity Guard | Zero Retention",
            x=994,
            y=792,
            w=432,
            h=64,
            fill="#bae6fd",
            stroke="#0284c7",
            bold=True,
        ),
        Box(
            id="agentforce_atlas",
            label="Agentforce Atlas Reasoning Engine & Private Connect",
            sublabel="Named Credentials (OAuth 2.0 JWT + mTLS) -> Vertex AI & MCP Actions",
            x=994,
            y=870,
            w=432,
            h=70,
            fill="#a5f3fc",
            stroke="#0e7490",
            bold=True,
        ),
        # ZONE 5: ENTERPRISE CONSUMERS
        Box(
            id="zone_users",
            label="ZONE 5: GCC Consumers & Governance",
            x=1476,
            y=190,
            w=320,
            h=770,
            fill="#f8fafc",
            stroke="#475569",
            dashed=True,
            is_container=True,
            font_color="#1e293b",
            font_size=12,
            bold=True,
        ),
        Box(
            id="persona_fin",
            label="Deal Desk & FinOps Execs",
            sublabel="Margin-Safe Renewal Plans\n(Routed to Gemini 1.5 Pro)",
            x=1496,
            y=254,
            w=280,
            h=110,
            fill="#ede9fe",
            stroke="#6d28d9",
            bold=True,
        ),
        Box(
            id="persona_noc",
            label="GCC Service & NOC Teams",
            sublabel="Instant P1 SLA Triage in Agentforce\n(Routed to Gemini 1.5 Flash)",
            x=1496,
            y=414,
            w=280,
            h=110,
            fill="#e0e7ff",
            stroke="#4338ca",
            bold=True,
        ),
        Box(
            id="persona_ciso",
            label="CISO & Compliance Audit",
            sublabel="Verifies 0 Raw PII Egress,\nSHA-256 Logs & Policy Denials",
            x=1496,
            y=574,
            w=280,
            h=110,
            fill="#fce7f3",
            stroke="#be185d",
            bold=True,
        ),
        Box(
            id="persona_rep",
            label="Enterprise Account Reps",
            sublabel="Grounded Customer 360 inside\nSalesforce Agentforce UI",
            x=1496,
            y=734,
            w=280,
            h=110,
            fill="#e0f2fe",
            stroke="#0369a1",
            bold=True,
        ),
        # Legend Strip
        Box(
            id="legend",
            label="Architecture Flow Legend",
            sublabel=(
                "[1] Amber: Edge CDC / Lakehouse Federation (Oracle -> Databricks)    "
                "[2] Blue Dashed: Zero-Copy Delta Sharing / Iceberg Uniform (No ETL Duplication)    "
                "[3] Emerald: Zero-Trust Private MCP over mTLS (Tokenized PII Only)    "
                "[4] Gold/Green: FinOps Tiered Routing (Flash 85% / Pro 15%)    "
                "[5] Cyan: Salesforce Private Connect & Data Cloud Zero-Copy"
            ),
            x=24,
            y=980,
            w=1772,
            h=72,
            fill="#f1f5f9",
            stroke="#64748b",
            font_size=11,
            bold=True,
        ),
    ]

    edges: list[Edge] = [
        # Oracle -> Edge CDC
        Edge("e1", "oracle_db", "edge_cdc", "1a. LogMiner CDC", "#d97706", exit_x=0.5, exit_y=1.0, entry_x=0.5, entry_y=0.0),
        # Legacy CRM -> MCP Gateway (local enclave)
        Edge("e2", "legacy_crm", "mcp_gateway", "Local SQLite/DB Enclave", "#0f766e", exit_x=0.5, exit_y=1.0, entry_x=0.5, entry_y=0.0),
        # Edge CDC -> Private Link -> ADLS Gen2
        Edge("e3", "edge_cdc", "priv_link_edge", "1b. Encrypted Outbound CDC", "#d97706", exit_x=1.0, exit_y=0.5, entry_x=0.0, entry_y=0.5),
        Edge("e4", "priv_link_edge", "adls_medallion", "CMEK Ingest", "#1d4ed8", exit_x=0.5, exit_y=1.0, entry_x=0.5, entry_y=0.0),
        # ADLS -> Unity Catalog / Federation
        Edge("e5", "adls_medallion", "lakehouse_fed", "Medallion Gold", "#1d4ed8", exit_x=0.5, exit_y=1.0, entry_x=0.5, entry_y=0.0),
        Edge("e6", "oracle_db", "lakehouse_fed", "2a. Zero-Copy Federation", "#2563eb", dashed=True, exit_x=1.0, exit_y=0.5, entry_x=0.0, entry_y=0.5, waypoints=((456, 282), (456, 509))),
        # Delta Sharing -> Vertex AI & Salesforce Data Cloud (Zero-Copy)
        Edge("e7", "delta_sharing", "vertex_bridge", "2b. Zero-Copy Delta Sharing", "#2563eb", dashed=True, exit_x=1.0, exit_y=0.35, entry_x=0.0, entry_y=0.5, waypoints=((956, 670), (956, 533))),
        Edge("e8", "delta_sharing", "sf_data_cloud", "2c. Zero-Copy Data Cloud", "#0284c7", dashed=True, exit_x=1.0, exit_y=0.75, entry_x=0.0, entry_y=0.5, waypoints=((956, 703), (956, 746))),
        # Vertex Bridge <-> Zero-Trust MCP Gateway (Private mTLS)
        Edge("e9", "vertex_bridge", "mcp_gateway", "3. Private MCP (mTLS, Tokenized Only)", "#047857", bidirectional=True, exit_x=0.0, exit_y=0.7, entry_x=1.0, entry_y=0.5, waypoints=((950, 548), (950, 962), (456, 962), (456, 756))),
        # FinOps Router -> Flash & Pro
        Edge("e10", "finops_router", "gemini_flash", "4a. Simple (85%)", "#15803d", exit_x=0.25, exit_y=1.0, entry_x=0.5, entry_y=0.0),
        Edge("e11", "finops_router", "gemini_pro", "4b. Complex (15%)", "#166534", exit_x=0.75, exit_y=1.0, entry_x=0.5, entry_y=0.0),
        Edge("e12", "gemini_flash", "vertex_bridge", "Tool Calls", "#15803d", bidirectional=True, exit_x=0.5, exit_y=1.0, entry_x=0.25, entry_y=0.0),
        Edge("e13", "gemini_pro", "vertex_bridge", "Reasoning", "#166534", bidirectional=True, exit_x=0.5, exit_y=1.0, entry_x=0.75, entry_y=0.0),
        # Salesforce internal & Private Connect -> Vertex AI
        Edge("e14", "sf_data_cloud", "einstein_trust", "Grounded Context", "#0891b2", exit_x=0.5, exit_y=1.0, entry_x=0.5, entry_y=0.0),
        Edge("e15", "einstein_trust", "agentforce_atlas", "Policy Checked", "#0284c7", exit_x=0.5, exit_y=1.0, entry_x=0.5, entry_y=0.0),
        Edge("e16", "agentforce_atlas", "finops_router", "5. Private Connect (JWT/mTLS)", "#0e7490", bidirectional=True, exit_x=1.0, exit_y=0.5, entry_x=1.0, entry_y=0.5, waypoints=((1458, 905), (1458, 338))),
        # Outputs to Personas
        Edge("e17", "gemini_pro", "persona_fin", "Strategic Briefs", "#6d28d9", exit_x=1.0, exit_y=0.5, entry_x=0.0, entry_y=0.5),
        Edge("e18", "gemini_flash", "persona_noc", "Fast Triage", "#4338ca", exit_x=1.0, exit_y=0.8, entry_x=0.0, entry_y=0.5, waypoints=((1452, 460), (1452, 469))),
        Edge("e19", "agentforce_atlas", "persona_rep", "Agentforce Actions", "#0369a1", exit_x=1.0, exit_y=0.7, entry_x=0.0, entry_y=0.5, waypoints=((1464, 919), (1464, 789))),
    ]
    return boxes, edges


def validate_no_overlaps(boxes: list[Box]) -> None:
    """Ensure non-container boxes never overlap one another."""
    leaf_boxes = [b for b in boxes if not b.is_container]
    for i, a in enumerate(leaf_boxes):
        for b in leaf_boxes[i + 1 :]:
            overlap_x = a.x < (b.x + b.w) and (a.x + a.w) > b.x
            overlap_y = a.y < (b.y + b.h) and (a.y + a.h) > b.y
            if overlap_x and overlap_y:
                raise ValueError(f"Layout overlap detected between '{a.id}' and '{b.id}'")


def generate_drawio_xml(boxes: list[Box], edges: list[Edge]) -> str:
    mxfile = ET.Element(
        "mxfile",
        attrib={
            "host": "app.diagrams.net",
            "agent": "GCC-Zero-Trust-Blueprint-Generator",
            "version": "24.7.17",
            "type": "device",
        },
    )
    diagram = ET.SubElement(
        mxfile,
        "diagram",
        attrib={"id": "gcc-hybrid-blueprint", "name": "Hybrid Edge-to-Cloud Architecture"},
    )
    model = ET.SubElement(
        diagram,
        "mxGraphModel",
        attrib={
            "dx": "1820",
            "dy": "1080",
            "grid": "1",
            "gridSize": "10",
            "guides": "1",
            "tooltips": "1",
            "connect": "1",
            "arrows": "1",
            "fold": "1",
            "page": "1",
            "pageScale": "1",
            "pageWidth": "1840",
            "pageHeight": "1080",
            "math": "0",
            "shadow": "0",
        },
    )
    root = ET.SubElement(model, "root")
    ET.SubElement(root, "mxCell", attrib={"id": "0"})
    ET.SubElement(root, "mxCell", attrib={"id": "1", "parent": "0"})

    for box in boxes:
        cell = ET.SubElement(
            root,
            "mxCell",
            attrib={
                "id": box.id,
                "value": box.drawio_label(),
                "style": box.drawio_style(),
                "vertex": "1",
                "parent": box.parent,
            },
        )
        ET.SubElement(
            cell,
            "mxGeometry",
            attrib={
                "x": str(box.x),
                "y": str(box.y),
                "width": str(box.w),
                "height": str(box.h),
                "as": "geometry",
            },
        )

    for edge in edges:
        cell = ET.SubElement(
            root,
            "mxCell",
            attrib={
                "id": edge.id,
                "value": edge.label,
                "style": edge.drawio_style(),
                "edge": "1",
                "parent": "1",
                "source": edge.source,
                "target": edge.target,
            },
        )
        geom = ET.SubElement(cell, "mxGeometry", attrib={"relative": "1", "as": "geometry"})
        if edge.waypoints:
            arr = ET.SubElement(geom, "Array", attrib={"as": "points"})
            for wx, wy in edge.waypoints:
                ET.SubElement(arr, "mxPoint", attrib={"x": str(wx), "y": str(wy)})

    ET.indent(mxfile, space="  ")
    return ET.tostring(mxfile, encoding="unicode", xml_declaration=True)


def generate_svg(boxes: list[Box], edges: list[Edge]) -> str:
    box_map = {b.id: b for b in boxes}
    lines: list[str] = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="1840" height="1080" viewBox="0 0 1840 1080">',
        '<rect width="1840" height="1080" fill="#ffffff"/>',
        '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        '<path d="M 0 1 L 10 5 L 0 9 z" fill="#334155"/></marker></defs>',
    ]

    # Draw containers first, then leaf boxes
    ordered = [b for b in boxes if b.is_container] + [b for b in boxes if not b.is_container]
    for b in ordered:
        dash = ' stroke-dasharray="6,4"' if b.dashed else ""
        rx = ' rx="8" ry="8"' if b.rounded and not b.is_db else ""
        sw = "2" if b.is_container or b.bold else "1.5"
        lines.append(
            f'<rect x="{b.x}" y="{b.y}" width="{b.w}" height="{b.h}" fill="{b.fill}" '
            f'stroke="{b.stroke}" stroke-width="{sw}"{dash}{rx}/>'
        )
        if b.is_container:
            lines.append(
                f'<text x="{b.x + 12}" y="{b.y + 20}" font-family="Segoe UI, Arial, sans-serif" '
                f'font-size="{b.font_size}" font-weight="700" fill="{b.font_color}">{html.escape(b.label)}</text>'
            )
        else:
            cx = b.x + b.w / 2
            sub_lines = b.sublabel.split("\n") if b.sublabel else []
            start_y = b.y + (b.h / 2) - (len(sub_lines) * 7)
            lines.append(
                f'<text x="{cx}" y="{start_y}" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" '
                f'font-size="{b.font_size}" font-weight="700" fill="{b.font_color}">{html.escape(b.label)}</text>'
            )
            for idx, sl in enumerate(sub_lines, start=1):
                sub_fill = "#cbd5e1" if b.fill == "#0f172a" else "#334155"
                lines.append(
                    f'<text x="{cx}" y="{start_y + idx * 14}" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" '
                    f'font-size="9.5" fill="{sub_fill}">{html.escape(sl)}</text>'
                )

    for e in edges:
        src = box_map[e.source]
        dst = box_map[e.target]
        sx = src.x + src.w * e.exit_x
        sy = src.y + src.h * e.exit_y
        tx = dst.x + dst.w * e.entry_x
        ty = dst.y + dst.h * e.entry_y
        pts = [(sx, sy), *e.waypoints, (tx, ty)]
        pts_str = " ".join(f"{px},{py}" for px, py in pts)
        dash = ' stroke-dasharray="6,4"' if e.dashed else ""
        start_mk = ' marker-start="url(#arrow)"' if e.bidirectional else ""
        lines.append(
            f'<polyline points="{pts_str}" fill="none" stroke="{e.stroke}" stroke-width="2"{dash} '
            f'marker-end="url(#arrow)"{start_mk}/>'
        )
        mid_x, mid_y = pts[len(pts) // 2]
        lines.append(
            f'<rect x="{mid_x - 62}" y="{mid_y - 10}" width="124" height="16" rx="3" fill="#ffffff" fill-opacity="0.9"/>'
            f'<text x="{mid_x}" y="{mid_y + 2}" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" '
            f'font-size="9" font-weight="700" fill="{e.stroke}">{html.escape(e.label)}</text>'
        )

    lines.append("</svg>")
    return "\n".join(lines)


def main() -> None:
    ARCH_DIR.mkdir(parents=True, exist_ok=True)
    boxes, edges = build_diagram_elements()
    validate_no_overlaps(boxes)

    drawio_xml = generate_drawio_xml(boxes, edges)
    DRAWIO_PATH.write_text(drawio_xml, encoding="utf-8")

    svg_text = generate_svg(boxes, edges)
    SVG_PATH.write_text(svg_text, encoding="utf-8")
    print(f"Generated {DRAWIO_PATH} and {SVG_PATH} ({len(boxes)} nodes, {len(edges)} flows).")


if __name__ == "__main__":
    main()
