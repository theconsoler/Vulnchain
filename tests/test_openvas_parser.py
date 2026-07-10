from parsers.openvas_parser import parse_openvas
from models.vuln_schema import Severity

def test_openvas_returns_results():
    results = parse_openvas("samples/sample_openvas.xml")
    assert len(results) > 0

def test_openvas_severity_valid():
    results = parse_openvas("samples/sample_openvas.xml")
    valid = {s.value for s in Severity}
    for r in results:
        assert r.severity.value in valid
