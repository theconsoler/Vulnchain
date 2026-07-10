from parsers.nessus_parser import parse_nessus
from models.vuln_schema import Severity

def test_nessus_returns_results():
    results = parse_nessus("samples/sample_nessus.xml")
    assert len(results) > 0

def test_nessus_host_ip_populated():
    results = parse_nessus("samples/sample_nessus.xml")
    for r in results:
        assert r.host_ip != "unknown"

def test_nessus_severity_valid():
    results = parse_nessus("samples/sample_nessus.xml")
    valid = {s.value for s in Severity}
    for r in results:
        assert r.severity.value in valid
