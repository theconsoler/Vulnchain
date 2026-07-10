import ipaddress
from graph.asset_classifier import ROLE_WEB_SERVER, ROLE_DATABASE, ROLE_SSH_SERVER


def get_subnet(ip: str, prefix: int = 24) -> str:
    """
    Returns the network address string for a given IP and prefix length.
    Example: get_subnet("192.168.1.45") -> "192.168.1.0/24"
    """
    try:
        network = ipaddress.ip_interface(f"{ip}/{prefix}").network
        return str(network)
    except ValueError:
        return "unknown"


def infer_edges(host_nodes: dict) -> list[tuple[str, str, dict]]:
    """
    Given a dict of {host_ip: node_attributes}, infer directed edges.
    Returns list of (source_ip, target_ip, edge_attributes).

    host_nodes structure:
    {
        "192.168.1.10": {
            "ports": [22, 443],
            "max_cvss": 7.5,
            "role": "WEB_SERVER",
            "criticality": 6,
            ...
        }
    }
    """
    edges = []
    ip_list = list(host_nodes.keys())

    # Build subnet groups
    subnet_groups: dict[str, list[str]] = {}
    for ip in ip_list:
        subnet = get_subnet(ip)
        if subnet not in subnet_groups:
            subnet_groups[subnet] = []
        subnet_groups[subnet].append(ip)

    added_edges = set()

    def add_edge(src: str, tgt: str, reason: str):
        key = (src, tgt)
        if key not in added_edges and src != tgt:
            target_cvss = host_nodes[tgt].get("max_cvss") or 0.0
            weight = round(1 / (target_cvss + 0.1), 4)
            edges.append((src, tgt, {"weight": weight, "reason": reason}))
            added_edges.add(key)

    # Strategy 1: Subnet proximity edges (bidirectional within same /24)
    for subnet, members in subnet_groups.items():
        if subnet == "unknown":
            continue
        for i, src in enumerate(members):
            for tgt in members[i + 1:]:
                add_edge(src, tgt, "subnet_proximity")
                add_edge(tgt, src, "subnet_proximity")

    # Strategy 2: Service reachability edges (cross-subnet)
    for src_ip, src_attrs in host_nodes.items():
        for tgt_ip, tgt_attrs in host_nodes.items():
            if src_ip == tgt_ip:
                continue
            tgt_role = tgt_attrs.get("role", "INTERNAL")
            tgt_ports = tgt_attrs.get("ports", [])

            # Any host can reach a web server
            if tgt_role == ROLE_WEB_SERVER:
                add_edge(src_ip, tgt_ip, "service_web_reachability")

            # Any host can reach an SSH server
            if tgt_role == ROLE_SSH_SERVER:
                add_edge(src_ip, tgt_ip, "service_ssh_reachability")

            # Web servers can reach database servers
            if tgt_role == ROLE_DATABASE and src_attrs.get("role") == ROLE_WEB_SERVER:
                add_edge(src_ip, tgt_ip, "service_db_reachability")

    return edges
