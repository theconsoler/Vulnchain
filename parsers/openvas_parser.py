import xml.etree.ElementTree as ET
from pathlib import Path
from models.vuln_schema import NormalizedVuln, Severity

SEVERITY_MAP = {
    "Critical": Severity.CRITICAL,
    "High":     Severity.HIGH,
    "Medium":   Severity.MEDIUM,
    "Low":      Severity.LOW,
    "Log":      Severity.INFO,
    "Debug":    Severity.INFO,
}

def parse_openvas(file_path: str) -> list[NormalizedVuln]:
    tree = ET.parse(Path(file_path))
    root = tree.getroot()
    results = []

    for result in root.iter("result"):
        host_el = result.find("host")
        host_ip = host_el.text.strip() if host_el is not None and host_el.text else "unknown"

        port_raw = result.findtext("port", "")
        port_num = None
        protocol = None
        if "/" in port_raw:
            parts    = port_raw.split("/")
            port_num = int(parts[0]) if parts[0].isdigit() else None
            protocol = parts[1] if len(parts) > 1 else None

        nvt       = result.find("nvt")
        plugin_id = nvt.get("oid") if nvt is not None else None
        title     = nvt.findtext("name", "Unknown") if nvt is not None else "Unknown"
        cvss_raw  = nvt.findtext("cvss_base") if nvt is not None else None

        cve_ids = []
        if nvt is not None:
            for ref in nvt.iter("ref"):
                if ref.get("type") == "cve":
                    cve_ids.append(ref.get("id"))

        threat      = result.findtext("threat", "Log")
        description = result.findtext("description")

        vuln = NormalizedVuln(
            vuln_id        = f"openvas_{plugin_id}_{host_ip}_{port_num}",
            source_scanner = "openvas",
            host_ip        = host_ip,
            port           = port_num,
            protocol       = protocol,
            cve_ids        = cve_ids,
            plugin_id      = plugin_id,
            title          = title,
            description    = description,
            severity       = SEVERITY_MAP.get(threat, Severity.INFO),
            cvss_score     = float(cvss_raw) if cvss_raw else None,
            raw_data       = {"threat": threat, "oid": plugin_id},
        )
        results.append(vuln)

    return results
