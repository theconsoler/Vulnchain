import argparse
import json
from pathlib import Path
from graph.graph_builder import build_graph, save_graph, generate_stats


def main():
    parser = argparse.ArgumentParser(description="VulnChain Phase 2 -- Asset Topology Builder")
    parser.add_argument(
        "--input",
        default="output/normalized_vulns.json",
        help="Path to Phase 1 normalized JSON output"
    )
    parser.add_argument(
        "--graph-output",
        default="output/asset_graph.json",
        help="Path to save the serialized NetworkX graph"
    )
    parser.add_argument(
        "--stats-output",
        default="output/graph_stats.json",
        help="Path to save the graph statistics JSON"
    )
    args = parser.parse_args()

    # Build graph
    G = build_graph(args.input)

    # Save graph
    save_graph(G, args.graph_output)

    # Generate and save stats
    stats = generate_stats(G)

    stats_path = Path(args.stats_output)
    stats_path.parent.mkdir(parents=True, exist_ok=True)
    with open(stats_path, "w") as f:
        json.dump(stats, f, indent=2)

    print(f"[+] Stats written to: {stats_path}")
    print("\n--- Graph Summary ---")
    print(f"  Nodes         : {stats['total_nodes']}")
    print(f"  Edges         : {stats['total_edges']}")
    print(f"  Connected     : {stats['is_connected']}")
    print(f"  Avg Out-Degree: {stats['avg_out_degree']}")
    print(f"  Nodes by Role :")
    for role, count in stats["nodes_by_role"].items():
        print(f"    {role:<25} {count}")
    print(f"  Nodes by Severity:")
    for sev, count in stats["nodes_by_severity"].items():
        print(f"    {sev:<25} {count}")


if __name__ == "__main__":
    main()
