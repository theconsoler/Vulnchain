import json
from pathlib import Path
import networkx as nx

from models.vuln_schema import NormalizedVuln, Severity
from graph.asset_classifier import classify_host
from graph.topology import infer_edges

SEVERITY_WEIGHT = {
    "critical":      10.0,
    "high":           8.0,
    "medium":         5.0,
    "low":            2.0,
    "informational":  0.5,
}


def load_normalized_vulns(json_path: str) -> list[NormalizedVuln]:
    """Load Phase 1 output JSON and reconstruct Pydantic objects."""
    with open(json_path, "r") as f:
        raw = json.load(f)
    return [NormalizedVuln.model_validate(record) for record in raw]


def build_host_nodes(vulns: list[NormalizedVuln]) -> dict:
    """
    Group vulnerabilities by host_ip and build node attribute dicts.
    Returns {host_ip: node_attributes}
    """
    host_map: dict[str, dict] = {}

    for vuln in vulns:
        ip = vuln.host_ip
        if ip not in host_map:
            host_map[ip] = {
                "hostname":    vuln.hostname,
                "ports":       [],
                "vulns":       [],
                "max_cvss":    0.0,
                "max_severity": "informational",
                "vuln_count":  0,
                "cve_ids":     [],
            }

        node = host_map[ip]

        # Accumulate ports
        if vuln.port and vuln.port not in node["ports"]:
            node["ports"].append(vuln.port)

        # Accumulate CVE IDs
        for cve in vuln.cve_ids:
            if cve not in node["cve_ids"]:
                node["cve_ids"].append(cve)

        # Track highest CVSS
        if vuln.cvss_score and vuln.cvss_score > node["max_cvss"]:
            node["max_cvss"] = vuln.cvss_score

        # Track highest severity
        current_weight  = SEVERITY_WEIGHT.get(node["max_severity"], 0)
        incoming_weight = SEVERITY_WEIGHT.get(vuln.severity.value, 0)
        if incoming_weight > current_weight:
            node["max_severity"] = vuln.severity.value

        # Store vuln summary
        node["vulns"].append({
            "vuln_id":   vuln.vuln_id,
            "title":     vuln.title,
            "severity":  vuln.severity.value,
            "cvss":      vuln.cvss_score,
            "cve_ids":   vuln.cve_ids,
        })
        node["vuln_count"] += 1

    # Classify each host after all vulns are loaded
    for ip, attrs in host_map.items():
        role, criticality = classify_host(attrs["ports"])
        attrs["role"]        = role
        attrs["criticality"] = criticality

    return host_map


def build_graph(json_path: str) -> nx.DiGraph:
    """
    Full Phase 2 pipeline:
    1. Load normalized vulns
    2. Build host node attributes
    3. Infer topology edges
    4. Construct and return NetworkX DiGraph
    """
    print(f"[*] Loading normalized vulns from: {json_path}")
    vulns = load_normalized_vulns(json_path)
    print(f"[+] Loaded {len(vulns)} vulnerability records")

    print("[*] Building host nodes...")
    host_nodes = build_host_nodes(vulns)
    print(f"[+] Found {len(host_nodes)} unique hosts")

    print("[*] Inferring topology edges...")
    edges = infer_edges(host_nodes)
    print(f"[+] Inferred {len(edges)} directed edges")

    # Construct graph
    G = nx.DiGraph()

    # Add nodes
    for ip, attrs in host_nodes.items():
        G.add_node(ip, **attrs)

    # Add edges
    for src, tgt, edge_attrs in edges:
        G.add_edge(src, tgt, **edge_attrs)

    print(f"[+] Graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G


def save_graph(G: nx.DiGraph, output_path: str) -> None:
    """Serialize graph to disk as JSON using NetworkX node-link format."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    data = nx.node_link_data(G)
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"[+] Graph saved to: {output_path}")


def load_graph(graph_path: str) -> nx.DiGraph:
    """Load a serialized graph from JSON."""
    with open(graph_path, "r") as f:
        data = json.load(f)
    return nx.node_link_graph(data, directed=True, multigraph=False)

def generate_stats(G: nx.DiGraph) -> dict:
    """Generate a summary statistics dict from the graph."""
    roles = {}
    severity_counts = {}

    for node, attrs in G.nodes(data=True):
        role = attrs.get("role", "UNKNOWN")
        roles[role] = roles.get(role, 0) + 1

        sev = attrs.get("max_severity", "informational")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "total_nodes":        G.number_of_nodes(),
        "total_edges":        G.number_of_edges(),
        "nodes_by_role":      roles,
        "nodes_by_severity":  severity_counts,
        "is_connected":       nx.is_weakly_connected(G) if G.number_of_nodes() > 0 else False,
        "avg_out_degree":     round(
            sum(d for _, d in G.out_degree()) / G.number_of_nodes(), 2
        ) if G.number_of_nodes() > 0 else 0,
    }
