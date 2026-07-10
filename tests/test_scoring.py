import pytest
import networkx as nx

from scoring.path_engine import (
    identify_perimeter_nodes,
    identify_critical_nodes,
    find_attack_paths,
    compute_path_betweenness,
    run_path_analysis,
)
from scoring.scorer import compute_node_score, score_all_nodes, build_prioritized_list


# ── Helper: Build test graphs ─────────────────────────────────────────────────

def make_single_node_graph() -> nx.DiGraph:
    """Graph with one WEB_SERVER node -- triggers fallback mode."""
    G = nx.DiGraph()
    G.add_node("172.16.0.20", **{
        "hostname":    "webserver.local",
        "ports":       [443],
        "vulns":       [{
            "vuln_id":  "qualys_38173_172.16.0.20_443",
            "title":    "OpenSSL Vulnerability",
            "severity": "high",
            "cvss":     7.5,
            "cve_ids":  ["CVE-2022-0778"],
        }],
        "max_cvss":    7.5,
        "max_cvss_v3": 7.5,
        "max_severity": "high",
        "max_epss":    0.7056,
        "vuln_count":  1,
        "cve_ids":     ["CVE-2022-0778"],
        "role":        "WEB_SERVER",
        "criticality": 6,
        "has_any_exploit": True,
        "enriched_cves": {
            "CVE-2022-0778": {
                "cvss_v3_score": 7.5,
                "epss_score":    0.7056,
                "has_exploit":   True,
            }
        },
        "enrichment_complete": True,
    })
    return G


def make_multi_node_graph() -> nx.DiGraph:
    """Graph with WEB_SERVER -> SSH_SERVER -> DATABASE path."""
    G = nx.DiGraph()
    G.add_node("10.0.0.1", **{
        "hostname":    "web01",
        "ports":       [443],
        "vulns":       [{"vuln_id": "v1", "title": "Web Vuln", "severity": "high",
                          "cvss": 7.5, "cve_ids": ["CVE-2021-0001"]}],
        "max_cvss":    7.5,
        "max_cvss_v3": 7.5,
        "max_severity": "high",
        "max_epss":    0.6,
        "vuln_count":  1,
        "cve_ids":     ["CVE-2021-0001"],
        "role":        "WEB_SERVER",
        "criticality": 6,
        "has_any_exploit": True,
        "enriched_cves": {"CVE-2021-0001": {"cvss_v3_score": 7.5, "epss_score": 0.6, "has_exploit": True}},
        "enrichment_complete": True,
    })
    G.add_node("10.0.0.2", **{
        "hostname":    "ssh01",
        "ports":       [22],
        "vulns":       [{"vuln_id": "v2", "title": "SSH Vuln", "severity": "medium",
                          "cvss": 5.0, "cve_ids": ["CVE-2021-0002"]}],
        "max_cvss":    5.0,
        "max_cvss_v3": 5.0,
        "max_severity": "medium",
        "max_epss":    0.3,
        "vuln_count":  1,
        "cve_ids":     ["CVE-2021-0002"],
        "role":        "SSH_SERVER",
        "criticality": 7,
        "has_any_exploit": False,
        "enriched_cves": {},
        "enrichment_complete": True,
    })
    G.add_node("10.0.0.3", **{
        "hostname":    "db01",
        "ports":       [5432],
        "vulns":       [{"vuln_id": "v3", "title": "DB Vuln", "severity": "critical",
                          "cvss": 9.0, "cve_ids": ["CVE-2021-0003"]}],
        "max_cvss":    9.0,
        "max_cvss_v3": 9.0,
        "max_severity": "critical",
        "max_epss":    0.05,
        "vuln_count":  1,
        "cve_ids":     ["CVE-2021-0003"],
        "role":        "DATABASE",
        "criticality": 9,
        "has_any_exploit": False,
        "enriched_cves": {},
        "enrichment_complete": True,
    })
    G.add_edge("10.0.0.1", "10.0.0.2", weight=0.2, reason="subnet_proximity")
    G.add_edge("10.0.0.2", "10.0.0.3", weight=0.1, reason="service_db_reachability")
    return G


# ── Path Engine Tests ─────────────────────────────────────────────────────────

def test_identify_perimeter_nodes():
    G = make_multi_node_graph()
    perimeter = identify_perimeter_nodes(G)
    assert "10.0.0.1" in perimeter

def test_identify_critical_nodes():
    G = make_multi_node_graph()
    critical = identify_critical_nodes(G)
    assert "10.0.0.3" in critical

def test_find_attack_paths():
    G = make_multi_node_graph()
    paths = find_attack_paths(G, ["10.0.0.1"], ["10.0.0.3"])
    assert len(paths) > 0
    assert paths[0][0] == "10.0.0.1"
    assert paths[0][-1] == "10.0.0.3"

def test_compute_path_betweenness_intermediate_node():
    G = make_multi_node_graph()
    paths = [["10.0.0.1", "10.0.0.2", "10.0.0.3"]]
    betweenness = compute_path_betweenness(G, paths)
    # Intermediate node should have highest betweenness
    assert betweenness["10.0.0.2"] > 0.0

def test_run_path_analysis_fallback_single_node():
    G = make_single_node_graph()
    result = run_path_analysis(G)
    assert result["fallback_mode"] is True
    assert result["path_count"] == 0

def test_run_path_analysis_multi_node():
    G = make_multi_node_graph()
    result = run_path_analysis(G)
    assert result["fallback_mode"] is False
    assert result["path_count"] > 0


# ── Scorer Tests ──────────────────────────────────────────────────────────────

def test_compute_node_score_structure():
    attrs = {
        "max_cvss_v3":    7.5,
        "max_epss":       0.7,
        "criticality":    6,
        "has_any_exploit": True,
        "max_severity":   "high",
    }
    score = compute_node_score(attrs, betweenness=0.0)
    assert "final_score" in score
    assert "base_score" in score
    assert score["exploit_multiplier"] == 1.5
    assert score["final_score"] > 0

def test_compute_node_score_exploit_multiplier():
    attrs_no_exploit = {"max_cvss_v3": 7.5, "max_epss": 0.5, "criticality": 6,
                        "has_any_exploit": False, "max_severity": "high"}
    attrs_exploit    = {"max_cvss_v3": 7.5, "max_epss": 0.5, "criticality": 6,
                        "has_any_exploit": True, "max_severity": "high"}
    score_no  = compute_node_score(attrs_no_exploit, 0.0)["final_score"]
    score_yes = compute_node_score(attrs_exploit, 0.0)["final_score"]
    assert score_yes > score_no

def test_compute_node_score_betweenness_increases_score():
    attrs = {"max_cvss_v3": 7.5, "max_epss": 0.5, "criticality": 6,
             "has_any_exploit": False, "max_severity": "high"}
    score_low  = compute_node_score(attrs, betweenness=0.0)["final_score"]
    score_high = compute_node_score(attrs, betweenness=1.0)["final_score"]
    assert score_high > score_low

def test_score_all_nodes_returns_sorted():
    G = make_multi_node_graph()
    scored = score_all_nodes(G)
    scores = [n["scoring"]["final_score"] for n in scored]
    assert scores == sorted(scores, reverse=True)

def test_build_prioritized_list_ranks():
    G = make_single_node_graph()
    scored = score_all_nodes(G)
    prioritized = build_prioritized_list(scored)
    assert len(prioritized) > 0
    assert prioritized[0]["rank"] == 1
    assert "vuln_score" in prioritized[0]
    assert "host_ip" in prioritized[0]

def test_score_all_nodes_sample_graph():
    """Test against the actual sample data graph structure."""
    G = make_single_node_graph()
    scored = score_all_nodes(G)
    assert len(scored) == 1
    assert scored[0]["ip"] == "172.16.0.20"
    assert scored[0]["scoring"]["final_score"] > 0
    assert scored[0]["has_exploit"] is True
