from parsers.qualys_parser import parse_qualys
from models.vuln_schema import Severity

def test_qualys_returns_results():
    results = parse_qualys("samples/sample_qualys.csv")
    assert len(results) > 0

def test_qualys_severity_valid():
    results = parse_qualys("samples/sample_qualys.csv")
    valid = {s.value for s in Severity}
    for r in results:
        assert r.severity.value in valid
