import json
import uuid
import os
from pathlib import Path
from flask import (Flask, request, jsonify, render_template,
                   redirect, url_for, send_file, make_response, current_app)
from flask_jwt_extended import (
    create_access_token, jwt_required,
    get_jwt_identity, set_access_cookies, unset_jwt_cookies
)
from werkzeug.utils import secure_filename

from app.auth import authenticate_user, register_user
from app.models import log_scan_run, get_recent_scans

ALLOWED_EXTENSIONS = {".nessus", ".xml", ".csv"}


def _allowed_file(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


def _get_db_path(app) -> str:
    return app.config["DB_PATH"]


def register_routes(app: Flask) -> None:

    @app.route("/", methods=["GET"])
    def index():
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html")

        limiter = current_app.extensions.get("limiter")
        if limiter:
            limiter.limit("5 per minute")(lambda: None)()

        data     = request.get_json() or request.form
        username = data.get("username", "").strip()
        password = data.get("password", "")

        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        if not authenticate_user(_get_db_path(app), username, password):
            return jsonify({"error": "Invalid credentials"}), 401

        token    = create_access_token(identity=username)
        response = jsonify({"message": "Login successful", "redirect": "/dashboard"})
        set_access_cookies(response, token)
        return response, 200

    @app.route("/logout", methods=["POST"])
    def logout():
        response = make_response(redirect(url_for("login")))
        unset_jwt_cookies(response)
        return response

    @app.route("/dashboard", methods=["GET"])
    @jwt_required()
    def dashboard():
        username = get_jwt_identity()
        score_report_path = Path(app.config["OUTPUT_FOLDER"]) / "score_report.json"
        report = {}
        if score_report_path.exists():
            with open(score_report_path) as f:
                report = json.load(f)
        recent_scans = get_recent_scans(_get_db_path(app))
        return render_template("overview.html",
                               username=username,
                               report=report,
                               recent_scans=recent_scans,
                               active="dashboard")

    @app.route("/graph", methods=["GET"])
    @jwt_required()
    def graph():
        username     = get_jwt_identity()
        graph_exists = (Path(app.config["OUTPUT_FOLDER"]) / "attack_graph.html").exists()
        return render_template("graph.html",
                               username=username,
                               graph_exists=graph_exists,
                               active="graph")

    @app.route("/vulnerabilities", methods=["GET"])
    @jwt_required()
    def vulnerabilities():
        username = get_jwt_identity()
        return render_template("vulns.html", username=username, active="vulns")

    @app.route("/reports", methods=["GET"])
    @jwt_required()
    def reports():
        username   = get_jwt_identity()
        output_dir = Path(app.config["OUTPUT_FOLDER"])
        return render_template("reports.html",
                               username=username,
                               html_exists=(output_dir / "vulnchain_report.html").exists(),
                               pdf_exists=(output_dir / "vulnchain_report.pdf").exists(),
                               active="reports")

    @app.route("/upload", methods=["GET"])
    @jwt_required()
    def upload_page():
        username = get_jwt_identity()
        return render_template("upload.html", username=username, active="upload")

    @app.route("/api/stats", methods=["GET"])
    @jwt_required()
    def api_stats():
        score_report_path = Path(app.config["OUTPUT_FOLDER"]) / "score_report.json"
        if not score_report_path.exists():
            return jsonify({"error": "No scan data available"}), 404
        with open(score_report_path) as f:
            return jsonify(json.load(f))

    @app.route("/api/vulns", methods=["GET"])
    @jwt_required()
    def api_vulns():
        prioritized_path = Path(app.config["OUTPUT_FOLDER"]) / "prioritized_vulns.json"
        if not prioritized_path.exists():
            return jsonify({"data": [], "total": 0, "page": 1, "pages": 1})

        with open(prioritized_path) as f:
            vulns = json.load(f)

        severity = request.args.get("severity", "").strip().lower()
        exploit  = request.args.get("exploit", "").strip().lower()
        if severity:
            vulns = [v for v in vulns if v.get("severity", "").lower() == severity]
        if exploit == "true":
            vulns = [v for v in vulns if v.get("has_exploit")]

        page     = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(10, int(request.args.get("per_page", 50))))
        total    = len(vulns)
        pages    = max(1, (total + per_page - 1) // per_page)
        page     = min(page, pages)
        start    = (page - 1) * per_page

        return jsonify({
            "data":     vulns[start:start + per_page],
            "total":    total,
            "page":     page,
            "pages":    pages,
            "per_page": per_page,
        })

    @app.route("/api/upload", methods=["POST"])
    @jwt_required()
    def api_upload():
        username = get_jwt_identity()

        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files["file"]
        if not file.filename:
            return jsonify({"error": "Empty filename"}), 400
        if not _allowed_file(file.filename):
            return jsonify({"error": f"Unsupported file type. Allowed: {ALLOWED_EXTENSIONS}"}), 400

        ext        = Path(file.filename).suffix.lower()
        safe_name  = f"{uuid.uuid4()}{ext}"
        upload_dir = Path(app.config["UPLOAD_FOLDER"])
        upload_dir.mkdir(parents=True, exist_ok=True)
        file_path  = upload_dir / safe_name
        file.save(str(file_path))

        from app.pipeline import start_pipeline_job
        job_id = start_pipeline_job(
            input_file = str(file_path),
            output_dir = app.config["OUTPUT_FOLDER"],
            db_path    = _get_db_path(app),
            username   = username,
        )
        return jsonify({"job_id": job_id, "status": "running"}), 202

    @app.route("/api/job/<job_id>", methods=["GET"])
    @jwt_required()
    def api_job_status(job_id):
        from app.models import get_job
        job = get_job(_get_db_path(app), job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        return jsonify({
            "job_id":     job["job_id"],
            "status":     job["status"],
            "progress":   job["progress"],
            "phase":      job["phase"],
            "vuln_count": job["vuln_count"],
            "node_count": job["node_count"],
            "path_count": job["path_count"],
            "error_msg":  job["error_msg"],
        })

    @app.route("/api/delta", methods=["GET"])
    @jwt_required()
    def api_delta():
        from app.models import get_last_two_snapshots
        latest, previous = get_last_two_snapshots(_get_db_path(app))

        if not latest:
            return jsonify({"error": "No scan data available"}), 404
        if not previous:
            return jsonify({
                "delta_available": False,
                "message": "Only one scan available. Run another scan to see delta."
            })

        latest_ids   = {v["vuln_id"] for v in latest}
        previous_ids = {v["vuln_id"] for v in previous}
        new_ids      = latest_ids - previous_ids
        resolved_ids = previous_ids - latest_ids
        unchanged    = latest_ids & previous_ids

        return jsonify({
            "delta_available":  True,
            "new_count":        len(new_ids),
            "resolved_count":   len(resolved_ids),
            "unchanged_count":  len(unchanged),
            "new_vulns":        [v for v in latest   if v["vuln_id"] in new_ids][:10],
            "resolved_vulns":   [v for v in previous if v["vuln_id"] in resolved_ids][:10],
        })

    @app.route("/api/download/html", methods=["GET"])
    @jwt_required()
    def download_html():
        path = Path(app.config["OUTPUT_FOLDER"]) / "vulnchain_report.html"
        if not path.exists():
            return jsonify({"error": "Report not generated yet"}), 404
        return send_file(str(path), as_attachment=True, download_name="vulnchain_report.html")

    @app.route("/api/download/pdf", methods=["GET"])
    @jwt_required()
    def download_pdf():
        path = Path(app.config["OUTPUT_FOLDER"]) / "vulnchain_report.pdf"
        if not path.exists():
            return jsonify({"error": "PDF not available"}), 404
        return send_file(str(path), as_attachment=True, download_name="vulnchain_report.pdf")

    @app.route("/output/attack_graph.html", methods=["GET"])
    @jwt_required()
    def serve_graph_html():
        path = Path(app.config["OUTPUT_FOLDER"]) / "attack_graph.html"
        if not path.exists():
            return "Graph not generated yet.", 404
        return send_file(str(path))

    @app.errorhandler(401)
    def unauthorized(e):
        return redirect(url_for("login"))

    @app.errorhandler(429)
    def too_many_requests(e):
        return jsonify({"error": "Too many login attempts. Wait 1 minute."}), 429
