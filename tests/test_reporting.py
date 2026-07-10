import json
import pickle
import pytest
import networkx as nx
from pathlib import Path

from reporting.graph_visualizer import _get_node_color, _get_node_size, _build_node_tooltip
from reporting.report_generator import generate_html_report
from reporting.pdf_exporter import WEASYPRINT_AVAILABLE


# ── Helper ────────────────────────────────────────────────────────────────────

def make_attrs(severity="high", has_exploit=False, cvss=7.5, epss=0.5, criticality=6):
    return {
        "max_severity":    severity,
        "has_any_exploit": has_exploit,
        "max_cvss_v3":     cvss,
        "max_cvss":        cvss,
        "max_epss":        epss,
        "criticality":     criticality,
        "hostname":        "test.local",
        "role":            "WEB_SERVER",
        "vuln_count":      1,
        "cve_ids":         ["CVE-2022-0001"],
    }


# ── Graph Visualizer Tests ────────────────────────────────────────────────────

def test_node_color_exploit():
    attrs = make_attrs(has_exploit=True)
    assert _get_node_color(attrs) == "#FF2D2D"

def test_node_color_critical():
    attrs = make_attrs(severity="critical", has_exploit=False)
    assert _get_node_color(attrs) == "#FF6B35"

def test_node_color_high():
    attrs = make_attrs(severity="high", has_exploit=False)
    assert _get_node_color(attrs) == "#FFB347"

def test_node_color_default():
    attrs = make_attrs(severity="informational", has_exploit=False)
    assert _get_node_color(attrs) == "#87CEEB"

def test_node_size_scales_with_risk():
    low_risk  = make_attrs(cvss=2.0, epss=0.01, criticality=3)
    high_risk = make_attrs(cvss=9.0, epss=0.9,  criticality=9)
    assert _get_node_size(high_risk) > _get_node_size(low_risk)

def test_node_size_within_bounds():
    attrs = make_attrs(cvss=10.0, epss=1.0, criticality=10)
    size  = _get_node_size(attrs, min_size=15, max_size=50)
    assert 15 <= size <= 50

def test_build_node_tooltip_contains_ip():
    attrs   = make_attrs()
    tooltip = _build_node_tooltip("192.168.1.1", attrs)
    assert "192.168.1.1" in tooltip

def test_build_node_tooltip_contains_epss():
    attrs   = make_attrs(epss=0.7056)
    tooltip = _build_node_tooltip("10.0.0.1", attrs)
    assert "0.7056" in tooltip or "70.6" in tooltip


# ── Report Generator Tests ────────────────────────────────────────────────────

def test_generate_html_report_creates_file(tmp_path):
    prioritized = [{
        "rank": 1, "host_ip": "192.168.1.1", "hostname": "web01",
        "role": "WEB_SERVER", "criticality": 6,
        "vuln_id": "test_1", "title": "Test Vuln", "severity": "high",
        "cvss": 7.5, "epss_score": 0.5, "has_exploit": True,
        "cve_ids": ["CVE-2022-0001"], "vuln_score": 3.37,
        "node_score": 3.37, "on_attack_path": False,
    }]
    report = {
        "total_nodes": 1, "total_vulns_ranked": 1,
        "nodes_with_exploit": 1, "vulns_high_epss": 1,
        "attack_path_count": 0, "fallback_mode": True,
        "top_5_priorities": prioritized,
    }
    scored_nodes = [{
        "ip": "192.168.1.1", "hostname": "web01", "role": "WEB_SERVER",
        "criticality": 6, "vuln_count": 1, "cve_ids": ["CVE-2022-0001"],
        "max_severity": "high", "has_exploit": True, "on_attack_path": False,
        "fallback_mode": True,
        "scoring": {"final_score": 3.37, "max_epss": 0.5,
                    "cvss_v3": 7.5, "epss_score": 0.5,
                    "criticality": 6, "betweenness": 0.0,
                    "base_score": 2.25, "exploit_multiplier": 1.5,
                    "centrality_mult": 1.0, "cvss_normalized": 0.75},
        "vulnerabilities": [{
            "vuln_id": "test_1", "title": "Test Vuln", "severity": "high",
            "cvss": 7.5, "cve_ids": ["CVE-2022-0001"],
            "epss_score": 0.5, "has_exploit": True, "vuln_score": 3.37,
        }],
    }]

    p_path  = tmp_path / "prioritized.json"
    r_path  = tmp_path / "report.json"
    sn_path = tmp_path / "scored_nodes.json"
    out     = tmp_path / "report.html"

    p_path.write_text(json.dumps(prioritized))
    r_path.write_text(json.dumps(report))
    sn_path.write_text(json.dumps(scored_nodes))

    generate_html_report(str(p_path), str(r_path), str(sn_path), str(out), template_dir="templates")

    assert out.exists()
    content = out.read_text()
    assert "VulnChain" in content
    assert "192.168.1.1" in content
    assert "EXPLOIT" in content

def test_html_report_contains_methodology(tmp_path):
    prioritized  = []
    report       = {"total_nodes": 0, "total_vulns_ranked": 0, "nodes_with_exploit": 0,
                    "vulns_high_epss": 0, "attack_path_count": 0, "fallback_mode": True,
                    "top_5_priorities": []}
    scored_nodes = []

    p_path  = tmp_path / "p.json"
    r_path  = tmp_path / "r.json"
    sn_path = tmp_path / "sn.json"
    out     = tmp_path / "out.html"

    p_path.write_text(json.dumps(prioritized))
    r_path.write_text(json.dumps(report))
    sn_path.write_text(json.dumps(scored_nodes))

    generate_html_report(str(p_path), str(r_path), str(sn_path), str(out), template_dir="templates")
    content = out.read_text()
    assert "Scoring Methodology" in content
    assert "epss_score" in content


# ── PDF Exporter Tests ────────────────────────────────────────────────────────

def test_weasyprint_import_flag():
    # Just verifies the flag is a bool -- does not require WeasyPrint to be installed
    assert isinstance(WEASYPRINT_AVAILABLE, bool)
