"""Validates the generated Draw.io XML and SVG architecture blueprint."""

from __future__ import annotations

import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT_DIR / "scripts" / "generate_blueprint.py"
DRAWIO_PATH = ROOT_DIR / "architecture" / "hybrid_edge_to_cloud_blueprint.drawio"
SVG_PATH = ROOT_DIR / "architecture" / "hybrid_edge_to_cloud_blueprint.svg"


def test_blueprint_generation_xml_and_zero_overlaps() -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT_PATH)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Generated" in proc.stdout
    assert DRAWIO_PATH.exists()
    assert SVG_PATH.exists()

    xml_text = DRAWIO_PATH.read_text(encoding="utf-8")
    root = ET.fromstring(xml_text)
    assert root.tag == "mxfile"

    cells = root.findall(".//mxCell")
    vertex_ids = {c.attrib["id"] for c in cells if c.attrib.get("vertex") == "1"}
    edge_cells = [c for c in cells if c.attrib.get("edge") == "1"]
    assert len(vertex_ids) >= 25
    assert len(edge_cells) >= 18

    # Ensure every edge points to valid source and target vertices
    for e in edge_cells:
        assert e.attrib["source"] in vertex_ids
        assert e.attrib["target"] in vertex_ids

    # Ensure all required enterprise systems are mapped in the Draw.io diagram
    for required_term in (
        "Oracle DB",
        "Azure Databricks",
        "Unity Catalog",
        "Delta Sharing",
        "Vertex AI",
        "Gemini 1.5 Flash",
        "Gemini 1.5 Pro",
        "Salesforce",
        "Agentforce",
        "Einstein Trust Layer",
        "Zero-Trust MCP Gateway",
    ):
        assert required_term in xml_text

    assert "Tally" not in xml_text

