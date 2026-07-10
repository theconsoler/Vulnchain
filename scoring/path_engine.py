import networkx as nx
from graph.asset_classifier import (
    ROLE_DOMAIN_CONTROLLER,
    ROLE_DATABASE,
    ROLE_WEB_SERVER,
    ROLE_DNS_SERVER,
    ROLE_SSH_SERVER,
)

# Nodes an attacker starts from (internet-facing)
PERIMETER_ROLES = {ROLE_WEB_SERVER, ROLE_DNS_SERVER}

# Nodes an attacker wants to reach (high-value targets)
CRITICAL_ROLES = {ROLE_DOMAIN_CONTROLLER, ROLE_DATABASE}

# If no domain controllers or databases exist, treat these as secondary targets
SECONDARY_TARGET_ROLES = {ROLE_SSH_SERVER}


def identify_perimeter_nodes(G: nx.DiGraph) -> list[str]:
    """Return all node IPs classified as perimeter/internet-facing."""
    return [
        node for node, attrs in G.nodes(data=True)
        if attrs.get("role") in PERIMETER_ROLES
    ]


def identify_critical_nodes(G: nx.DiGraph) -> list[str]:
    """Return all node IPs classified as critical assets."""
    critical = [
        node for node, attrs in G.nodes(data=True)
        if attrs.get("role") in CRITICAL_ROLES
    ]
    if critical:
        return critical

    # Fallback: if no DC or DB nodes exist, use SSH servers as targets
    secondary = [
        node for node, attrs in G.nodes(data=True)
        if attrs.get("role") in SECONDARY_TARGET_ROLES
    ]
    return secondary


def find_attack_paths(
    G: nx.DiGraph,
    perimeter_nodes: list[str],
    critical_nodes: list[str],
    max_path_length: int = 6,
) -> list[list[str]]:
    """
    Find all simple directed paths from any perimeter node to any critical node.
    Limits path length to avoid combinatorial explosion on large graphs.
    Returns list of paths, where each path is a list of node IPs.
    """
    all_paths = []

    for src in perimeter_nodes:
        for tgt in critical_nodes:
            if src == tgt:
                continue
            try:
                paths = list(nx.all_simple_paths(G, source=src, target=tgt, cutoff=max_path_length))
                all_paths.extend(paths)
            except nx.NetworkXError:
                continue

    return all_paths


def compute_path_betweenness(
    G: nx.DiGraph,
    attack_paths: list[list[str]],
) -> dict[str, float]:
    """
    Calculate how many attack paths pass through each node.
    Normalize to 0.0-1.0 range.
    Returns {node_ip: normalized_betweenness}
    """
    path_counts: dict[str, int] = {node: 0 for node in G.nodes()}

    for path in attack_paths:
        # Count intermediate nodes only (not source and target)
        for node in path[1:-1]:
            if node in path_counts:
                path_counts[node] += 1

    # Also count source and target nodes -- they are on every path through them
    for path in attack_paths:
        if path:
            path_counts[path[0]]  = path_counts.get(path[0], 0) + 1
        if len(path) > 1:
            path_counts[path[-1]] = path_counts.get(path[-1], 0) + 1

    # Normalize
    max_count = max(path_counts.values()) if path_counts else 1
    if max_count == 0:
        return {node: 0.0 for node in G.nodes()}

    return {
        node: round(count / max_count, 4)
        for node, count in path_counts.items()
    }


def run_path_analysis(G: nx.DiGraph) -> dict:
    """
    Full path analysis pipeline.
    Returns a dict with perimeter nodes, critical nodes, all paths,
    and per-node betweenness scores.

    Falls back gracefully when graph is too small for path analysis.
    """
    perimeter = identify_perimeter_nodes(G)
    critical  = identify_critical_nodes(G)

    result = {
        "perimeter_nodes":  perimeter,
        "critical_nodes":   critical,
        "attack_paths":     [],
        "path_count":       0,
        "betweenness":      {node: 0.0 for node in G.nodes()},
        "fallback_mode":    False,
    }

    if not perimeter:
        print("  [!] No perimeter nodes found. Running in fallback mode.")
        result["fallback_mode"] = True
        return result

    if not critical:
        print("  [!] No critical asset nodes found. Running in fallback mode.")
        result["fallback_mode"] = True
        return result

    if G.number_of_edges() == 0:
        print("  [!] Graph has no edges. Running in fallback mode.")
        result["fallback_mode"] = True
        return result

    attack_paths = find_attack_paths(G, perimeter, critical)

    if not attack_paths:
        print("  [!] No attack paths found between perimeter and critical nodes.")
        print("      This can happen when perimeter and critical nodes are not connected.")
        print("      Running in fallback mode -- scoring by node attributes only.")
        result["fallback_mode"] = True
        return result

    betweenness = compute_path_betweenness(G, attack_paths)

    result["attack_paths"] = attack_paths
    result["path_count"]   = len(attack_paths)
    result["betweenness"]  = betweenness
    result["fallback_mode"] = False

    return result
