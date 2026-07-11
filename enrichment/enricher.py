import json
from pathlib import Path
import networkx as nx

from enrichment.nvd_client import fetch_cve
from enrichment.epss_client import fetch_epss_batch


def collect_all_cves(G: nx.DiGraph) -> list[str]:
    """Collect every unique CVE ID across all graph nodes."""
    all_cves = set()
    for _, attrs in G.nodes(data=True):
        for cve_id in attrs.get("cve_ids", []):
            if cve_id and cve_id.startswith("CVE-"):
                all_cves.add(cve_id)
    return sorted(all_cves)


def enrich_graph(G: nx.DiGraph, verbose: bool = True) -> nx.DiGraph:
    """
    Full Phase 3 enrichment pipeline:
    1. Collect all unique CVE IDs from the graph
    2. Fetch EPSS scores in batch (fast, one round trip per 100 CVEs)
    3. Fetch NVD data per CVE (rate-limited, cached)
    4. Merge enrichment data back into each node
    5. Return enriched graph
    """
    all_cves = collect_all_cves(G)

    if not all_cves:
        print("[!] No CVE IDs found in graph. Nothing to enrich.")
        _mark_all_nodes_complete(G)
        return G

    if verbose:
        print(f"[*] Found {len(all_cves)} unique CVE IDs across {G.number_of_nodes()} nodes")

    # Step 1: Fetch EPSS scores in batch (fast)
    if verbose:
        print(f"[*] Fetching EPSS scores for {len(all_cves)} CVEs...")
    epss_results = fetch_epss_batch(all_cves)
    if verbose:
        print(f"[+] EPSS fetch complete")

    # Step 2: Fetch NVD data per CVE (rate-limited)
    if verbose:
        print(f"[*] Fetching NVD data (rate-limited -- this takes time)...")
    nvd_results = {}
    for i, cve_id in enumerate(all_cves):
        if verbose:
            print(f"  [{i+1}/{len(all_cves)}] {cve_id}", end="")
        nvd_data = fetch_cve(cve_id)
        nvd_results[cve_id] = nvd_data
        if verbose:
            status = "cached" if not nvd_data.get("enriched") else "fetched"
            score  = nvd_data.get("cvss_v3_score", "N/A")
            print(f" -- CVSS={score} ({status})")

    # Step 3: Merge into graph nodes
    if verbose:
        print("[*] Writing enrichment data into graph nodes...")

    for node_ip, attrs in G.nodes(data=True):
        node_cves      = attrs.get("cve_ids", [])
        enriched_cves  = {}
        max_epss       = 0.0
        max_cvss_v3    = attrs.get("max_cvss") or 0.0

        for cve_id in node_cves:
            if not cve_id or not cve_id.startswith("CVE-"):
                continue

            nvd  = nvd_results.get(cve_id, {})
            epss = epss_results.get(cve_id, {})

            # Merge NVD and EPSS into one record
            merged = {**nvd}
            merged["epss_score"]      = epss.get("epss_score")
            merged["epss_percentile"] = epss.get("epss_percentile")

            # Flag has_exploit if EPSS score is high (>= 0.1 threshold)
            epss_score = epss.get("epss_score") or 0.0
            merged["has_exploit"] = epss_score >= 0.1

            enriched_cves[cve_id] = merged

            # Track max EPSS across node's CVEs
            if epss_score > max_epss:
                max_epss = epss_score

            # Update max CVSS if NVD has a higher score
            nvd_score = nvd.get("cvss_v3_score") or 0.0
            if nvd_score > max_cvss_v3:
                max_cvss_v3 = nvd_score

        # Write back into node
        G.nodes[node_ip]["enriched_cves"]      = enriched_cves
        G.nodes[node_ip]["max_epss"]           = round(max_epss, 4)
        G.nodes[node_ip]["max_cvss_v3"]        = max_cvss_v3
        G.nodes[node_ip]["enrichment_complete"] = True
        G.nodes[node_ip]["has_any_exploit"]    = any(
            v.get("has_exploit") for v in enriched_cves.values()
        )

    if verbose:
        print(f"[+] Enrichment complete for all {G.number_of_nodes()} nodes")

    return G


def _mark_all_nodes_complete(G: nx.DiGraph) -> None:
    for node_ip in G.nodes():
        G.nodes[node_ip]["enriched_cves"]      = {}
        G.nodes[node_ip]["max_epss"]           = 0.0
        G.nodes[node_ip]["max_cvss_v3"]        = 0.0
        G.nodes[node_ip]["enrichment_complete"] = True
        G.nodes[node_ip]["has_any_exploit"]    = False


def generate_enrichment_report(G: nx.DiGraph) -> dict:
    """Generate a summary of enrichment results across the graph."""
    total_cves      = 0
    enriched_cves   = 0
    exploit_count   = 0
    high_epss_count = 0
    nodes_with_exploit = 0

    for _, attrs in G.nodes(data=True):
        node_enriched = attrs.get("enriched_cves", {})
        total_cves   += len(attrs.get("cve_ids", []))
        enriched_cves += len(node_enriched)

        for cve_id, cve_data in node_enriched.items():
            if cve_data.get("has_exploit"):
                exploit_count += 1
            epss = cve_data.get("epss_score") or 0.0
            if epss >= 0.5:
                high_epss_count += 1

        if attrs.get("has_any_exploit"):
            nodes_with_exploit += 1

    top_risk_nodes = sorted(
        [
            {
                "ip":           node,
                "role":         attrs.get("role"),
                "max_epss":     attrs.get("max_epss", 0.0),
                "max_cvss_v3":  attrs.get("max_cvss_v3", 0.0),
                "has_exploit":  attrs.get("has_any_exploit", False),
                "criticality":  attrs.get("criticality", 0),
                "vuln_count":   attrs.get("vuln_count", 0),
            }
            for node, attrs in G.nodes(data=True)
        ],
        key=lambda x: (x["has_exploit"], x["max_epss"], x["max_cvss_v3"]),
        reverse=True,
    )

    return {
        "total_nodes":          G.number_of_nodes(),
        "total_cve_ids":        total_cves,
        "enriched_cve_ids":     enriched_cves,
        "cves_with_exploit":    exploit_count,
        "cves_high_epss":       high_epss_count,
        "nodes_with_exploit":   nodes_with_exploit,
        "top_risk_nodes":       top_risk_nodes[:10],
    }
