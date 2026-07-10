import pytest
import networkx as nx
from graph.asset_classifier import classify_host, ROLE_DATABASE, ROLE_WEB_SERVER, ROLE_INTERNAL, ROLE_SSH_SERVER
from graph.topology import get_subnet, infer_edges
from graph.graph_builder import build_host_nodes, build_graph, generate_stats
from models.vuln_schema import NormalizedVuln, Severity


# ── Classifier Tests ──────────────────────────────────────────────────────────

def test_classify_database_host():
    role, score = classify_host([3306, 22])
    assert role == ROLE_DATABASE
    assert score == 9

def test_classify_web_server():
    role, score = classify_host([80, 443])
    assert role == ROLE_WEB_SERVER
    assert score == 6

def test_classify_internal_host():
    role, score = classify_host([9999, 12345])
    assert role == ROLE_INTERNAL
    assert score == 3

def test_classify_empty_ports():
    role, score = classify_host([])
    assert role == ROLE_INTERNAL


# ── Topology Tests ────────────────────────────────────────────────────────────

def test_get_subnet_standard():
    assert get_subnet("192.168.1.45") == "192.168.1.0/24"

def test_get_subnet_different_host():
    assert get_subnet("10.0.0.99") == "10.0.0.0/24"

def test_get_subnet_invalid():
    assert get_subnet("not_an_ip") == "unknown"

def test_infer_edges_same_subnet():
    nodes = {
        "192.168.1.10": {"ports": [22], "max_cvss": 5.0, "role": ROLE_SSH_SERVER},
        "192.168.1.20": {"ports": [80], "max_cvss": 7.5, "role": ROLE_WEB_SERVER},
    }
    edges = infer_edges(nodes)
    sources = [(s, t) for s, t, _ in edges]
    assert ("192.168.1.10", "192.168.1.20") in sources
    assert ("192.168.1.20", "192.168.1.10") in sources

def test_infer_edges_no_self_loops():
    nodes = {
        "10.0.0.1": {"ports": [443], "max_cvss": 6.0, "role": ROLE_WEB_SERVER},
    }
    edges = infer_edges(nodes)
    for src, tgt, _ in edges:
        assert src != tgt


# ── Graph Builder Tests ───────────────────────────────────────────────────────

def make_test_vuln(ip: str, port: int, cvss: float, severity: Severity) -> NormalizedVuln:
    return NormalizedVuln(
        vuln_id        = f"test_{ip}_{port}",
        source_scanner = "nessus",
        host_ip        = ip,
        port           = port,
        protocol       = "tcp",
        title          = "Test Vulnerability",
        severity       = severity,
        cvss_score     = cvss,
        cve_ids        = ["CVE-2021-0001"],
    )

def test_build_host_nodes_groups_by_ip():
    vulns = [
        make_test_vuln("192.168.1.10", 443, 7.5, Severity.HIGH),
        make_test_vuln("192.168.1.10", 22,  5.0, Severity.MEDIUM),
        make_test_vuln("192.168.1.20", 3306, 9.0, Severity.CRITICAL),
    ]
    nodes = build_host_nodes(vulns)
    assert len(nodes) == 2
    assert nodes["192.168.1.10"]["vuln_count"] == 2
    assert nodes["192.168.1.20"]["max_cvss"] == 9.0

def test_build_host_nodes_max_severity():
    vulns = [
        make_test_vuln("10.0.0.5", 80, 3.0, Severity.LOW),
        make_test_vuln("10.0.0.5", 443, 9.0, Severity.CRITICAL),
    ]
    nodes = build_host_nodes(vulns)
    assert nodes["10.0.0.5"]["max_severity"] == "critical"

def test_build_graph_returns_digraph():
    G = build_graph("output/normalized_vulns.json")
    assert isinstance(G, nx.DiGraph)

def test_build_graph_has_nodes():
    G = build_graph("output/normalized_vulns.json")
    assert G.number_of_nodes() > 0

def test_generate_stats_keys():
    G = build_graph("output/normalized_vulns.json")
    stats = generate_stats(G)
    assert "total_nodes" in stats
    assert "total_edges" in stats
    assert "nodes_by_role" in stats
    assert "nodes_by_severity" in stats
