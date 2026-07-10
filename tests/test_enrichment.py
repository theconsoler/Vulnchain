import pytest
import pickle
import networkx as nx
from unittest.mock import patch, MagicMock

from enrichment.nvd_client import _parse_nvd_response, _empty_enrichment
from enrichment.epss_client import _empty_epss
from enrichment.enricher import collect_all_cves, enrich_graph, generate_enrichment_report


# ── Helper: Build a minimal test graph ───────────────────────────────────────

def make_test_graph() -> nx.DiGraph:
    G = nx.DiGraph()
    G.add_node("192.168.1.10", **{
        "hostname":     "webserver.local",
        "ports":        [443],
        "vulns":        [],
        "max_cvss":     7.5,
        "max_severity": "high",
        "vuln_count":   1,
        "cve_ids":      ["CVE-2022-0778"],
        "role":         "WEB_SERVER",
        "criticality":  6,
    })
    G.add_node("10.0.0.5", **{
        "hostname":     None,
        "ports":        [22],
        "vulns":        [],
        "max_cvss":     5.0,
        "max_severity": "medium",
        "vuln_count":   1,
        "cve_ids":      ["CVE-2008-5161"],
        "role":         "SSH_SERVER",
        "criticality":  7,
    })
    G.add_node("172.16.0.20", **{
        "hostname":     None,
        "ports":        [53],
        "vulns":        [],
        "max_cvss":     0.0,
        "max_severity": "informational",
        "vuln_count":   1,
        "cve_ids":      [],
        "role":         "DNS_SERVER",
        "criticality":  5,
    })
    return G


# ── NVD Client Tests ──────────────────────────────────────────────────────────

def test_parse_nvd_response_extracts_score():
    fake_cve_item = {
        "metrics": {
            "cvssMetricV31": [{
                "cvssData": {
                    "baseScore":    7.5,
                    "baseSeverity": "HIGH",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                }
            }]
        },
        "weaknesses": [{
            "description": [{"lang": "en", "value": "CWE-835"}]
        }]
    }
    result = _parse_nvd_response("CVE-2022-0778", fake_cve_item)
    assert result["cvss_v3_score"] == 7.5
    assert result["cvss_v3_severity"] == "HIGH"
    assert result["cwe"] == "CWE-835"
    assert result["enriched"] is True

def test_empty_enrichment_structure():
    result = _empty_enrichment("CVE-0000-0000", reason="not_found")
    assert result["enriched"] is False
    assert result["cvss_v3_score"] is None
    assert result["has_exploit"] is False
    assert result["skip_reason"] == "not_found"


# ── EPSS Client Tests ─────────────────────────────────────────────────────────

def test_empty_epss_structure():
    result = _empty_epss("CVE-0000-0000")
    assert result["epss_score"] is None
    assert result["epss_percentile"] is None


# ── Enricher Tests ────────────────────────────────────────────────────────────

def test_collect_all_cves():
    G = make_test_graph()
    cves = collect_all_cves(G)
    assert "CVE-2022-0778" in cves
    assert "CVE-2008-5161" in cves

def test_collect_all_cves_excludes_empty():
    G = make_test_graph()
    cves = collect_all_cves(G)
    # Node 172.16.0.20 has empty cve_ids
    assert len(cves) == 2

def test_enrich_graph_adds_enriched_cves():
    G = make_test_graph()

    fake_nvd = {
        "CVE-2022-0778": {
            "cve_id": "CVE-2022-0778",
            "cvss_v3_score": 7.5,
            "cvss_v3_severity": "HIGH",
            "cvss_v3_vector": None,
            "cwe": None,
            "has_exploit": False,
            "enriched": True,
            "source": "nvd",
        },
        "CVE-2008-5161": {
            "cve_id": "CVE-2008-5161",
            "cvss_v3_score": 4.0,
            "cvss_v3_severity": "MEDIUM",
            "cvss_v3_vector": None,
            "cwe": None,
            "has_exploit": False,
            "enriched": True,
            "source": "nvd",
        }
    }
    fake_epss = {
        "CVE-2022-0778": {"epss_score": 0.97, "epss_percentile": 0.99},
        "CVE-2008-5161": {"epss_score": 0.03, "epss_percentile": 0.45},
    }

    with patch("enrichment.enricher.fetch_cve", side_effect=lambda cve: fake_nvd.get(cve, {})):
        with patch("enrichment.enricher.fetch_epss_batch", return_value=fake_epss):
            G = enrich_graph(G, verbose=False)

    assert G.nodes["192.168.1.10"]["enrichment_complete"] is True
    assert "CVE-2022-0778" in G.nodes["192.168.1.10"]["enriched_cves"]
    assert G.nodes["192.168.1.10"]["max_epss"] == 0.97
    assert G.nodes["192.168.1.10"]["has_any_exploit"] is True

def test_enrich_graph_no_cves_node():
    G = make_test_graph()

    with patch("enrichment.enricher.fetch_cve", return_value={}):
        with patch("enrichment.enricher.fetch_epss_batch", return_value={}):
            G = enrich_graph(G, verbose=False)

    # Node with no CVEs should still be marked complete
    assert G.nodes["172.16.0.20"]["enrichment_complete"] is True
    assert G.nodes["172.16.0.20"]["max_epss"] == 0.0

def test_generate_enrichment_report_keys():
    G = make_test_graph()
    with patch("enrichment.enricher.fetch_cve", return_value=_empty_enrichment("X")):
        with patch("enrichment.enricher.fetch_epss_batch", return_value={}):
            G = enrich_graph(G, verbose=False)
    report = generate_enrichment_report(G)
    assert "total_nodes" in report
    assert "total_cve_ids" in report
    assert "top_risk_nodes" in report
