import argparse
import json
from pathlib import Path

from scoring.scorer import score_all_nodes, build_prioritized_list, generate_score_report
from scoring.path_engine import run_path_analysis


def main():
    parser = argparse.ArgumentParser(description="VulnChain Phase 4 -- Attack Path Scoring Engine")
    parser.add_argument("--input", default="output/enriched_graph.json")
    parser.add_argument(
        "--output",
        default="output/prioritized_vulns.json",
        help="Path to save prioritized vulnerability list"
    )
    parser.add_argument(
        "--report",
        default="output/score_report.json",
        help="Path to save scoring summary report"
    )
    args = parser.parse_args()

    # Load enriched graph
    print(f"[*] Loading enriched graph from: {args.input}")
    from graph.graph_builder import load_graph
    G = load_graph(args.input)
    print(f"[+] Graph loaded: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    # Run scoring
    scored_nodes = score_all_nodes(G)

    # Build flat prioritized list
    prioritized  = build_prioritized_list(scored_nodes)

    # Get path result for report
    path_result  = run_path_analysis(G)

    # Generate report
    report       = generate_score_report(scored_nodes, prioritized, path_result)

    # Save prioritized vulns
    output_path  = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(prioritized, f, indent=2)
    print(f"[+] Prioritized vulnerabilities saved to: {output_path}")

    # Save report
    report_path  = Path(args.report)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Score report saved to: {report_path}")

    # Print summary
    print("\n--- Scoring Summary ---")
    print(f"  Total nodes scored    : {report['total_nodes']}")
    print(f"  Total vulns ranked    : {report['total_vulns_ranked']}")
    print(f"  Nodes with exploit    : {report['nodes_with_exploit']}")
    print(f"  Vulns high EPSS(>=0.5): {report['vulns_high_epss']}")
    print(f"  Attack paths found    : {report['attack_path_count']}")
    print(f"  Fallback mode         : {report['fallback_mode']}")

    if prioritized:
        print("\n--- Top Priority Vulnerabilities (Patch These First) ---")
        for v in prioritized[:5]:
            exploit_flag = "[EXPLOIT]" if v["has_exploit"] else ""
            print(
                f"  Rank {v['rank']:>2} | {v['host_ip']:<18} | "
                f"{v['title'][:40]:<40} | "
                f"score={v['vuln_score']:.4f} | "
                f"epss={v['epss_score'] or 0:.4f} | "
                f"cvss={v['cvss']} {exploit_flag}"
            )


if __name__ == "__main__":
    main()
