import pandas as pd
from pathlib import Path
from models.vuln_schema import NormalizedVuln, Severity

SEVERITY_MAP = {
    1: Severity.INFO,
    2: Severity.LOW,
    3: Severity.MEDIUM,
    4: Severity.HIGH,
    5: Severity.CRITICAL,
}

def parse_qualys(file_path: str) -> list[NormalizedVuln]:
    df = pd.read_csv(Path(file_path), dtype=str)
    df.columns = [c.strip().upper() for c in df.columns]
    results = []

    for _, row in df.iterrows():
        host_ip      = row.get("IP", "unknown")
        hostname     = row.get("DNS") or row.get("FQDN")
        port_raw     = row.get("PORT")
        protocol     = row.get("PROTOCOL")
        qid          = row.get("QID")
        title        = row.get("TITLE", "Unknown")
        severity_raw = row.get("SEVERITY")
        cvss_raw     = row.get("CVSS BASE")
        cve_raw      = row.get("CVE ID", "")
        solution     = row.get("SOLUTION")
        description  = row.get("THREAT")

        cve_raw = str(cve_raw) if cve_raw and pd.notna(cve_raw) else ""
        cve_ids = [c.strip() for c in cve_raw.split(",") if c.strip().startswith("CVE")]

        try:
            severity_int = int(float(severity_raw)) if severity_raw else 1
        except (ValueError, TypeError):
            severity_int = 1

        vuln = NormalizedVuln(
            vuln_id        = f"qualys_{qid}_{host_ip}_{port_raw}",
            source_scanner = "qualys",
            host_ip        = host_ip,
            hostname       = hostname if pd.notna(hostname) else None,
            port           = int(float(port_raw)) if port_raw and str(port_raw).replace(".", "").isdigit() else None,
            protocol       = protocol if pd.notna(protocol) else None,
            cve_ids        = cve_ids,
            plugin_id      = qid,
            title          = title,
            description    = description if pd.notna(description) else None,
            severity       = SEVERITY_MAP.get(severity_int, Severity.INFO),
            cvss_score     = float(cvss_raw) if cvss_raw and pd.notna(cvss_raw) else None,
            solution       = solution if pd.notna(solution) else None,
            raw_data       = {"qid": qid, "severity_raw": severity_raw},
        )
        results.append(vuln)

    return results
