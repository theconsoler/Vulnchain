import json
from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader


def generate_html_report(
    prioritized_path: str,
    score_report_path: str,
    scored_nodes_path: str,
    output_path: str,
    template_dir: str = "templates",
) -> str:
    """
    Render the Jinja2 HTML report template with real scoring data.
    Returns path to generated HTML file.
    """
    with open(prioritized_path) as f:
        prioritized = json.load(f)

    with open(score_report_path) as f:
        report = json.load(f)

    with open(scored_nodes_path) as f:
        scored_nodes = json.load(f)

    env      = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("report_template.html")

    rendered = template.render(
        prioritized   = prioritized,
        report        = report,
        scored_nodes  = scored_nodes,
        generated_at  = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(rendered)

    print(f"[+] HTML report saved to: {output_path}")
    return str(output_path)
