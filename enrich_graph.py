import argparse
import json
from pathlib import Path
import networkx as nx

from enrichment.enricher import enrich_graph, generate_enrichment_report


def main():
    parser = argparse.ArgumentParser(description="VulnChain Phase 3 -- CVE Enrichment Engine")
    parser.add_argument("--input",  default="output/asset_graph.json")
    parser.add_argument("--output", default="output/enriched_graph.json")
    parser.add_argument(
        "--report",
        default="output/enrichment_report.json",
        help="Path to save enrichment report JSON"
    )
    args = parser.parse_args()

    # Load Phase 2 graph
    print(f"[*] Loading graph from: {args.input}")
    from graph.graph_builder import load_graph, save_graph
    G = load_graph(args.input)
    print(f"[+] Graph loaded: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    # Run enrichment
    G = enrich_graph(G, verbose=True)

    # Save enriched graph
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    save_graph(G, str(output_path))
    print(f"[+] Enriched graph saved to: {output_path}")

    # Generate and save report
    report = generate_enrichment_report(G)
    report_path = Path(args.report)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Enrichment report saved to: {report_path}")

    # Print summary
    print("\n--- Enrichment Summary ---")
    print(f"  Total nodes           : {report['total_nodes']}")
    print(f"  Total CVE IDs         : {report['total_cve_ids']}")
    print(f"  CVEs enriched         : {report['enriched_cve_ids']}")
    print(f"  CVEs with exploit     : {report['cves_with_exploit']}")
    print(f"  CVEs high EPSS (>=0.5): {report['cves_high_epss']}")
    print(f"  Nodes with exploit    : {report['nodes_with_exploit']}")

    if report["top_risk_nodes"]:
        print("\n  Top Risk Nodes:")
        for n in report["top_risk_nodes"]:
            exploit_flag = "[EXPLOIT]" if n["has_exploit"] else ""
            print(
                f"    {n['ip']:<18} role={n['role']:<22} "
                f"epss={n['max_epss']:.4f}  cvss={n['max_cvss_v3']}  {exploit_flag}"
            )


if __name__ == "__main__":
    main()
