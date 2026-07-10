import xml.etree.ElementTree as ET
from pathlib import Path
from models.vuln_schema import NormalizedVuln, Severity

SEVERITY_MAP = {
    "0": Severity.INFO,
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
    "4": Severity.CRITICAL,
}

def parse_nessus(file_path: str) -> list[NormalizedVuln]:
    tree = ET.parse(Path(file_path))
    root = tree.getroot()
    results = []

    for report_host in root.iter("ReportHost"):
        host_ip = report_host.get("name", "unknown")
        hostname = None

        for tag in report_host.iter("tag"):
            if tag.get("name") == "host-fqdn":
                hostname = tag.text

        for item in report_host.iter("ReportItem"):
            plugin_id  = item.get("pluginID")
            title      = item.get("pluginName", "Unknown")
            sev_raw    = item.get("severity", "0")
            port_raw   = item.get("port")
            protocol   = item.get("protocol")

            cve_ids  = [c.text for c in item.findall("cve") if c.text]
            cvss_raw = item.findtext("cvss_base_score")
            description = item.findtext("description")
            solution    = item.findtext("solution")

            vuln = NormalizedVuln(
                vuln_id        = f"nessus_{plugin_id}_{host_ip}_{port_raw}",
                source_scanner = "nessus",
                host_ip        = host_ip,
                hostname       = hostname,
                port           = int(port_raw) if port_raw and port_raw.isdigit() else None,
                protocol       = protocol,
                cve_ids        = cve_ids,
                plugin_id      = plugin_id,
                title          = title,
                description    = description,
                severity       = SEVERITY_MAP.get(sev_raw, Severity.INFO),
                cvss_score     = float(cvss_raw) if cvss_raw else None,
                solution       = solution,
                raw_data       = {"plugin_id": plugin_id, "severity_raw": sev_raw},
            )
            results.append(vuln)

    return results
