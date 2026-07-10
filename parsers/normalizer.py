from pathlib import Path
from parsers.nessus_parser import parse_nessus
from parsers.openvas_parser import parse_openvas
from parsers.qualys_parser import parse_qualys
from models.vuln_schema import NormalizedVuln

def detect_and_parse(file_path: str) -> list[NormalizedVuln]:
    path   = Path(file_path)
    suffix = path.suffix.lower()

    if suffix == ".csv":
        return parse_qualys(file_path)

    if suffix in [".xml", ".nessus"]:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(2000)

        if "NessusClientData" in content:
            return parse_nessus(file_path)
        elif "<report" in content.lower() and "nvt" in content.lower():
            return parse_openvas(file_path)
        else:
            raise ValueError(f"Unrecognized XML format: {file_path}")

    raise ValueError(f"Unsupported file extension: {suffix}")

