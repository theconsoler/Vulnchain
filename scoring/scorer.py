import networkx as nx
from scoring.path_engine import run_path_analysis


SEVERITY_TO_CVSS_FALLBACK = {
    "critical":      9.0,
    "high":          7.5,
    "medium":        5.0,
    "low":           2.0,
    "informational": 0.5,
}


def compute_node_score(
    attrs: dict,
    betweenness: float,
) -> dict:
    """
    Compute the final risk score for a single node.

    Formula:
    base_score         = (cvss_v3 / 10.0) x epss_score x criticality
    exploit_multiplier = 1.5 if has_exploit else 1.0
    centrality_mult    = 1.0 + (betweenness x 2.0)
    final_score        = base_score x exploit_multiplier x centrality_mult
    """
    # CVSS: prefer NVD v3.1, fall back to scanner CVSS, fall back to severity label
    cvss_v3 = (
        attrs.get("max_cvss_v3")
        or attrs.get("max_cvss")
        or SEVERITY_TO_CVSS_FALLBACK.get(attrs.get("max_severity", "informational"), 0.5)
    )
    cvss_normalized = min(cvss_v3 / 10.0, 1.0)

    # EPSS: 0.0 if not enriched
    epss = attrs.get("max_epss") or 0.0

    # Criticality: asset value weight (3-10)
    criticality = attrs.get("criticality", 3)

    # Exploit multiplier
    has_exploit      = attrs.get("has_any_exploit", False)
    exploit_mult     = 1.5 if has_exploit else 1.0

    # Centrality multiplier (1.0 to 3.0)
    centrality_mult  = 1.0 + (betweenness * 2.0)

    # Base score
    base_score       = cvss_normalized * epss * criticality

    # If EPSS is zero (not enriched or genuinely zero), use CVSS only
    if epss == 0.0:
        base_score   = cvss_normalized * criticality * 0.1

    # Final score
    final_score      = round(base_score * exploit_mult * centrality_mult, 4)

    return {
        "cvss_v3":           cvss_v3,
        "cvss_normalized":   round(cvss_normalized, 4),
        "epss_score":        epss,
        "criticality":       criticality,
        "betweenness":       round(betweenness, 4),
        "base_score":        round(base_score, 4),
        "exploit_multiplier": exploit_mult,
        "centrality_mult":   round(centrality_mult, 4),
        "final_score":       final_score,
    }


def score_all_nodes(G: nx.DiGraph) -> list[dict]:
    """
    Run full Phase 4 scoring pipeline.
    Returns list of scored node records sorted by final_score descending.
    """
    print("[*] Running attack path analysis...")
    path_result  = run_path_analysis(G)
    betweenness  = path_result["betweenness"]
    fallback     = path_result["fallback_mode"]

    if fallback:
        print("  [i] Fallback mode active -- scoring by node attributes only")
    else:
        print(f"  [+] Found {path_result['path_count']} attack paths")
        print(f"  [+] Perimeter nodes : {path_result['perimeter_nodes']}")
        print(f"  [+] Critical nodes  : {path_result['critical_nodes']}")

    print("[*] Computing risk scores...")
    scored_nodes = []

    for node_ip, attrs in G.nodes(data=True):
        node_betweenness = betweenness.get(node_ip, 0.0)
        scores           = compute_node_score(attrs, node_betweenness)

        # Build per-CVE scored records
        vuln_records = []
        enriched_cves = attrs.get("enriched_cves", {})

        for vuln in attrs.get("vulns", []):
            cve_ids    = vuln.get("cve_ids", [])
            vuln_epss  = 0.0
            vuln_cvss  = vuln.get("cvss") or scores["cvss_v3"]
            has_exploit = False

            # Pull best EPSS and exploit flag from enriched CVEs for this vuln
            for cve_id in cve_ids:
                cve_data   = enriched_cves.get(cve_id, {})
                cve_epss   = cve_data.get("epss_score") or 0.0
                if cve_epss > vuln_epss:
                    vuln_epss = cve_epss
                if cve_data.get("has_exploit"):
                    has_exploit = True

            vuln_score = round(
                (min(vuln_cvss / 10.0, 1.0))
                * max(vuln_epss, 0.01)
                * attrs.get("criticality", 3)
                * (1.5 if has_exploit else 1.0)
                * scores["centrality_mult"],
                4
            )

            vuln_records.append({
                "vuln_id":      vuln.get("vuln_id"),
                "title":        vuln.get("title"),
                "severity":     vuln.get("severity"),
                "cvss":         vuln_cvss,
                "cve_ids":      cve_ids,
                "epss_score":   vuln_epss,
                "has_exploit":  has_exploit,
                "vuln_score":   vuln_score,
            })

        vuln_records.sort(key=lambda x: x["vuln_score"], reverse=True)

        scored_nodes.append({
            "ip":               node_ip,
            "hostname":         attrs.get("hostname"),
            "role":             attrs.get("role"),
            "criticality":      attrs.get("criticality"),
            "vuln_count":       attrs.get("vuln_count", 0),
            "cve_ids":          attrs.get("cve_ids", []),
            "max_severity":     attrs.get("max_severity"),
            "scoring":          scores,
            "vulnerabilities":  vuln_records,
            "on_attack_path":   node_betweenness > 0.0,
            "has_exploit":      attrs.get("has_any_exploit", False),
            "fallback_mode":    fallback,
        })

    scored_nodes.sort(key=lambda x: x["scoring"]["final_score"], reverse=True)
    return scored_nodes


def build_prioritized_list(scored_nodes: list[dict]) -> list[dict]:
    """
    Flatten scored nodes into a flat prioritized vulnerability list.
    Each record is one vulnerability on one host with its priority rank.
    """
    flat_list = []
    rank = 1

    for node in scored_nodes:
        for vuln in node.get("vulnerabilities", []):
            flat_list.append({
                "rank":         rank,
                "host_ip":      node["ip"],
                "hostname":     node["hostname"],
                "role":         node["role"],
                "criticality":  node["criticality"],
                "vuln_id":      vuln["vuln_id"],
                "title":        vuln["title"],
                "severity":     vuln["severity"],
                "cvss":         vuln["cvss"],
                "epss_score":   vuln["epss_score"],
                "has_exploit":  vuln["has_exploit"],
                "cve_ids":      vuln["cve_ids"],
                "vuln_score":   vuln["vuln_score"],
                "node_score":   node["scoring"]["final_score"],
                "on_attack_path": node["on_attack_path"],
            })
            rank += 1

    flat_list.sort(key=lambda x: x["vuln_score"], reverse=True)
    for i, item in enumerate(flat_list):
        item["rank"] = i + 1

    return flat_list


def generate_score_report(
    scored_nodes: list[dict],
    prioritized: list[dict],
    path_result: dict = None,
) -> dict:
    """Generate a summary statistics report for the scoring run."""
    exploit_nodes     = sum(1 for n in scored_nodes if n["has_exploit"])
    on_path_nodes     = sum(1 for n in scored_nodes if n["on_attack_path"])
    high_epss_vulns   = sum(1 for v in prioritized if (v["epss_score"] or 0) >= 0.5)
    exploit_vulns     = sum(1 for v in prioritized if v["has_exploit"])

    top_5 = prioritized[:5]

    return {
        "total_nodes":         len(scored_nodes),
        "total_vulns_ranked":  len(prioritized),
        "nodes_with_exploit":  exploit_nodes,
        "nodes_on_attack_path": on_path_nodes,
        "vulns_with_exploit":  exploit_vulns,
        "vulns_high_epss":     high_epss_vulns,
        "fallback_mode":       scored_nodes[0]["fallback_mode"] if scored_nodes else True,
        "attack_path_count":   path_result["path_count"] if path_result else 0,
        "top_5_priorities":    top_5,
    }
