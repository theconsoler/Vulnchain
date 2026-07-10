import json
import uuid
import traceback
import threading
from pathlib import Path

from parsers.normalizer import detect_and_parse
from graph.graph_builder import build_graph, save_graph, load_graph
from enrichment.enricher import enrich_graph
from scoring.scorer import score_all_nodes, build_prioritized_list, generate_score_report
from scoring.path_engine import run_path_analysis
from reporting.graph_visualizer import generate_graph_html
from reporting.report_generator import generate_html_report
from reporting.pdf_exporter import export_to_pdf, WEASYPRINT_AVAILABLE


def _run_pipeline_thread(input_file, output_dir, db_path, job_id, username):
    from app.models import update_job, log_scan_run, save_scan_snapshot
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    ext = Path(input_file).suffix.lower()
    paths = {
        "normalized":   str(output_dir / "normalized_vulns.json"),
        "graph":        str(output_dir / "asset_graph.json"),
        "enriched":     str(output_dir / "enriched_graph.json"),
        "prioritized":  str(output_dir / "prioritized_vulns.json"),
        "score_report": str(output_dir / "score_report.json"),
        "scored_nodes": str(output_dir / "scored_nodes.json"),
        "graph_html":   str(output_dir / "attack_graph.html"),
        "report_html":  str(output_dir / "vulnchain_report.html"),
        "report_pdf":   str(output_dir / "vulnchain_report.pdf"),
    }
    try:
        update_job(db_path, job_id, status="running", progress="Parsing scanner file...", phase=1)
        vulns = detect_and_parse(input_file)
        with open(paths["normalized"], "w") as f:
            json.dump([v.model_dump() for v in vulns], f, indent=2, default=str)

        update_job(db_path, job_id, progress="Building asset topology graph...", phase=2)
        G = build_graph(paths["normalized"])
        save_graph(G, paths["graph"])

        update_job(db_path, job_id, progress="Enriching with NVD and EPSS data...", phase=3)
        G = load_graph(paths["graph"])
        G = enrich_graph(G, verbose=False)
        save_graph(G, paths["enriched"])

        update_job(db_path, job_id, progress="Scoring attack paths...", phase=4)
        G = load_graph(paths["enriched"])
        scored_nodes = score_all_nodes(G)
        prioritized  = build_prioritized_list(scored_nodes)
        path_result  = run_path_analysis(G)
        report       = generate_score_report(scored_nodes, prioritized, path_result)
        with open(paths["prioritized"],  "w") as f:
            json.dump(prioritized, f, indent=2)
        with open(paths["score_report"], "w") as f:
            json.dump(report, f, indent=2)
        with open(paths["scored_nodes"], "w") as f:
            json.dump(scored_nodes, f, indent=2, default=str)

        update_job(db_path, job_id, progress="Generating visualizations and report...", phase=5)
        generate_graph_html(graph_path=paths["enriched"], output_path=paths["graph_html"], prioritized_path=paths["prioritized"])
        generate_html_report(prioritized_path=paths["prioritized"], score_report_path=paths["score_report"], scored_nodes_path=paths["scored_nodes"], output_path=paths["report_html"])
        if WEASYPRINT_AVAILABLE:
            try:
                export_to_pdf(paths["report_html"], paths["report_pdf"])
            except Exception:
                pass

        log_scan_run(db_path, username, Path(input_file).name, ext.lstrip("."), len(vulns), G.number_of_nodes(), "success")
        save_scan_snapshot(db_path, username, prioritized)
        update_job(db_path, job_id, status="complete", progress="Pipeline complete.", phase=5, vuln_count=len(vulns), node_count=G.number_of_nodes(), path_count=path_result.get("path_count", 0))

    except Exception as e:
        print(f"[Pipeline ERROR] job={job_id}\n{traceback.format_exc()}")
        update_job(db_path, job_id, status="error", progress="Pipeline failed.", error_msg=str(e))


def start_pipeline_job(input_file, output_dir, db_path, username):
    from app.models import create_job
    job_id = str(uuid.uuid4())
    create_job(db_path, job_id, username)
    thread = threading.Thread(target=_run_pipeline_thread, args=(input_file, output_dir, db_path, job_id, username), daemon=True)
    thread.start()
    return job_id
