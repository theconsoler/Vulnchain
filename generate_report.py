import argparse
import json
from pathlib import Path

from reporting.graph_visualizer import generate_graph_html
from reporting.report_generator import generate_html_report
from reporting.pdf_exporter import export_to_pdf
from scoring.scorer import score_all_nodes, build_prioritized_list, generate_score_report
from scoring.path_engine import run_path_analysis


def main():
    parser = argparse.ArgumentParser(description="VulnChain Phase 5 -- Report and Visualization Generator")
    parser.add_argument("--graph", default="output/enriched_graph.json")
    parser.add_argument("--prioritized", default="output/prioritized_vulns.json")
    parser.add_argument("--score-report",default="output/score_report.json")
    parser.add_argument("--graph-html",  default="output/attack_graph.html")
    parser.add_argument("--report-html", default="output/vulnchain_report.html")
    parser.add_argument("--report-pdf",  default="output/vulnchain_report.pdf")
    parser.add_argument("--no-pdf",      action="store_true", help="Skip PDF export")
    args = parser.parse_args()

    print("[*] Loading enriched graph...")
    from graph.graph_builder import load_graph
    G = load_graph(args.graph)
    print(f"[+] Graph loaded: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    # Re-run scoring to get scored_nodes for report
    print("[*] Re-computing scores for report generation...")
    scored_nodes = score_all_nodes(G)
    prioritized  = build_prioritized_list(scored_nodes)
    path_result  = run_path_analysis(G)
    report       = generate_score_report(scored_nodes, prioritized, path_result)

    # Save updated outputs
    with open(args.prioritized, "w") as f:
        json.dump(prioritized, f, indent=2)
    with open(args.score_report, "w") as f:
        json.dump(report, f, indent=2)

    # Save scored_nodes for template
    scored_nodes_path = "output/scored_nodes.json"
    with open(scored_nodes_path, "w") as f:
        json.dump(scored_nodes, f, indent=2, default=str)

    # Step 1: Generate interactive graph
    print("\n[*] Generating interactive attack graph...")
    generate_graph_html(
        graph_path       = args.graph,
        output_path      = args.graph_html,
        prioritized_path = args.prioritized,
    )

    # Step 2: Generate HTML report
    print("\n[*] Generating HTML report...")
    generate_html_report(
        prioritized_path  = args.prioritized,
        score_report_path = args.score_report,
        scored_nodes_path = scored_nodes_path,
        output_path       = args.report_html,
    )

    # Step 3: Export to PDF
    if not args.no_pdf:
        print("\n[*] Exporting to PDF...")
        try:
            export_to_pdf(args.report_html, args.report_pdf)
        except Exception as e:
            print(f"  [!] PDF export failed: {e}")
            print("  [i] HTML report is still available at:", args.report_html)
    else:
        print("\n[i] PDF export skipped (--no-pdf flag)")

    print("\n--- Phase 5 Complete ---")
    print(f"  Interactive Graph : {args.graph_html}")
    print(f"  HTML Report       : {args.report_html}")
    if not args.no_pdf:
        print(f"  PDF Report        : {args.report_pdf}")
    print("\nOpen the HTML files in your browser to view:")
    print(f"  xdg-open {args.graph_html}")
    print(f"  xdg-open {args.report_html}")


if __name__ == "__main__":
    main()
