import json
from pathlib import Path
import networkx as nx

try:
    from pyvis.network import Network
    PYVIS_AVAILABLE = True
except ImportError:
    PYVIS_AVAILABLE = False


SEVERITY_COLORS = {
    "critical":      "#FF6B35",
    "high":          "#FFB347",
    "medium":        "#FFD700",
    "low":           "#90EE90",
    "informational": "#87CEEB",
}

ROLE_SHAPES = {
    "DOMAIN_CONTROLLER": "diamond",
    "DATABASE":          "database",
    "WEB_SERVER":        "dot",
    "SSH_SERVER":        "triangle",
    "DNS_SERVER":        "square",
    "INTERNAL":          "dot",
}


def _get_node_color(attrs: dict) -> str:
    if attrs.get("has_any_exploit"):
        return "#FF2D2D"
    severity = attrs.get("max_severity", "informational")
    return SEVERITY_COLORS.get(severity, "#87CEEB")


def _get_node_size(attrs: dict, min_size: int = 15, max_size: int = 50) -> int:
    cvss = attrs.get("max_cvss_v3") or attrs.get("max_cvss") or 0.0
    epss = attrs.get("max_epss") or 0.0
    criticality = attrs.get("criticality", 3)
    raw_score = (cvss / 10.0) * max(epss, 0.1) * criticality
    normalized = min(raw_score / 10.0, 1.0)
    return int(min_size + (normalized * (max_size - min_size)))


def _build_node_tooltip(node_ip: str, attrs: dict) -> str:
    hostname    = attrs.get("hostname") or "N/A"
    role        = attrs.get("role", "UNKNOWN")
    severity    = attrs.get("max_severity", "N/A")
    cvss        = attrs.get("max_cvss_v3") or attrs.get("max_cvss") or "N/A"
    epss        = attrs.get("max_epss", 0.0)
    exploit     = "YES -- ACTIVE EXPLOIT" if attrs.get("has_any_exploit") else "No"
    vuln_count  = attrs.get("vuln_count", 0)
    cve_ids     = ", ".join(attrs.get("cve_ids", [])[:3])
    if len(attrs.get("cve_ids", [])) > 3:
        cve_ids += f" (+{len(attrs.get('cve_ids', [])) - 3} more)"

    return (
        f"IP: {node_ip}\n"
        f"Hostname: {hostname}\n"
        f"Role: {role}\n"
        f"Severity: {severity.upper()}\n"
        f"CVSS v3.1: {cvss}\n"
        f"EPSS: {epss:.4f} ({epss*100:.1f}% exploit prob)\n"
        f"Active Exploit: {exploit}\n"
        f"Vulnerabilities: {vuln_count}\n"
        f"CVEs: {cve_ids or 'None'}"
    )


def generate_graph_html(
    graph_path: str,
    output_path: str,
    prioritized_path: str = None,
) -> str:
    """
    Generate interactive Pyvis HTML graph from enriched NetworkX graph.
    Returns path to generated HTML file.
    """
    if not PYVIS_AVAILABLE:
        raise ImportError("pyvis is not installed. Run: pip install pyvis==0.3.2")
   
    from graph.graph_builder import load_graph
    G = load_graph(graph_path)

    # Load scoring data if available for node sizing
    node_scores = {}
    if prioritized_path and Path(prioritized_path).exists():
        with open(prioritized_path) as f:
            prioritized = json.load(f)
        for item in prioritized:
            ip = item["host_ip"]
            if ip not in node_scores or item["node_score"] > node_scores[ip]:
                node_scores[ip] = item["node_score"]

    net = Network(
        height="750px",
        width="100%",
        bgcolor="#0d1117",
        font_color="#c9d1d9",
        directed=True,
        notebook=False,
    )

    net.set_options("""
    {
        "nodes": {
            "font": {"size": 12, "color": "#c9d1d9"},
            "borderWidth": 2,
            "shadow": true
        },
        "edges": {
            "arrows": {"to": {"enabled": true, "scaleFactor": 0.8}},
            "color": {"color": "#3d444d", "highlight": "#58a6ff"},
            "smooth": {"type": "curvedCW", "roundness": 0.2},
            "shadow": false
        },
        "physics": {
            "enabled": true,
            "stabilization": {"iterations": 100},
            "barnesHut": {
                "gravitationalConstant": -8000,
                "springLength": 200,
                "springConstant": 0.04
            }
        },
        "interaction": {
            "hover": true,
            "tooltipDelay": 100,
            "zoomView": true,
            "navigationButtons": true
        }
    }
    """)

    for node_ip, attrs in G.nodes(data=True):
        color     = _get_node_color(attrs)
        size      = _get_node_size(attrs)
        shape     = ROLE_SHAPES.get(attrs.get("role", "INTERNAL"), "dot")
        tooltip   = _build_node_tooltip(node_ip, attrs)
        label     = f"{node_ip}\n{attrs.get('role', '')}"
        border    = "#FF2D2D" if attrs.get("has_any_exploit") else color

        net.add_node(
            node_ip,
            label=label,
            title=tooltip,
            color={"background": color, "border": border, "highlight": {"background": color, "border": "#ffffff"}},
            size=size,
            shape=shape,
        )

    for src, tgt, edge_attrs in G.edges(data=True):
        reason = edge_attrs.get("reason", "")
        weight = edge_attrs.get("weight", 1.0)
        edge_color = "#58a6ff" if "service" in reason else "#3d444d"
        net.add_edge(src, tgt, color=edge_color, title=f"Reason: {reason}\nWeight: {weight}")

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    net.save_graph(output_path)

    _inject_legend(output_path)

    print(f"[+] Interactive graph saved to: {output_path}")
    return output_path


def _inject_legend(html_path: str) -> None:
    """Inject a color legend into the Pyvis HTML output."""
    legend_html = """
    <div style="position:fixed;top:10px;right:10px;background:#161b22;border:1px solid #30363d;
                border-radius:8px;padding:16px;z-index:1000;font-family:monospace;color:#c9d1d9;
                min-width:200px;">
        <div style="font-weight:bold;margin-bottom:10px;color:#58a6ff;">VulnChain -- Risk Legend</div>
        <div><span style="color:#FF2D2D;">&#9679;</span> Active Exploit Confirmed</div>
        <div><span style="color:#FF6B35;">&#9679;</span> Critical Severity</div>
        <div><span style="color:#FFB347;">&#9679;</span> High Severity</div>
        <div><span style="color:#FFD700;">&#9679;</span> Medium Severity</div>
        <div><span style="color:#90EE90;">&#9679;</span> Low Severity</div>
        <div><span style="color:#87CEEB;">&#9679;</span> Informational</div>
        <div style="margin-top:10px;font-size:11px;color:#8b949e;">Node size = Risk Score<br>Click node for details</div>
    </div>
    """
    with open(html_path, "r") as f:
        content = f.read()
    content = content.replace("</body>", legend_html + "\n</body>")
    with open(html_path, "w") as f:
        f.write(content)
