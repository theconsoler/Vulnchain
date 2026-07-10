import json
import time
import os
from pathlib import Path
import requests
from dotenv import load_dotenv

load_dotenv()

NVD_API_BASE  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY   = os.getenv("NVD_API_KEY", "")
CACHE_DIR     = Path("cache/nvd")
REQUEST_DELAY = 6.5   # seconds between requests without API key (5 req/30s = 6s min)
API_KEY_DELAY = 0.7   # seconds between requests with API key (50 req/30s)


def _cache_path(cve_id: str) -> Path:
    return CACHE_DIR / f"{cve_id}.json"


def _load_cache(cve_id: str) -> dict | None:
    path = _cache_path(cve_id)
    if path.exists():
        with open(path, "r") as f:
            return json.load(f)
    return None


def _save_cache(cve_id: str, data: dict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with open(_cache_path(cve_id), "w") as f:
        json.dump(data, f, indent=2)


def fetch_cve(cve_id: str) -> dict:
    """
    Fetch CVE data from NVD API v2.0.
    Returns a normalized dict with CVSS v3.1 data.
    Returns an empty enrichment dict if the CVE is not found or API fails.
    """
    cached = _load_cache(cve_id)
    if cached is not None:
        return cached

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    delay = API_KEY_DELAY if NVD_API_KEY else REQUEST_DELAY

    try:
        response = requests.get(
            NVD_API_BASE,
            params={"cveId": cve_id},
            headers=headers,
            timeout=15,
        )
        time.sleep(delay)

        if response.status_code == 404:
            result = _empty_enrichment(cve_id, reason="not_found")
            _save_cache(cve_id, result)
            return result

        if response.status_code != 200:
            print(f"  [!] NVD API returned {response.status_code} for {cve_id}")
            return _empty_enrichment(cve_id, reason=f"http_{response.status_code}")

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            result = _empty_enrichment(cve_id, reason="no_data")
            _save_cache(cve_id, result)
            return result

        cve_item = vulnerabilities[0].get("cve", {})
        result   = _parse_nvd_response(cve_id, cve_item)
        _save_cache(cve_id, result)
        return result

    except requests.exceptions.Timeout:
        print(f"  [!] Timeout fetching {cve_id}")
        return _empty_enrichment(cve_id, reason="timeout")
    except requests.exceptions.RequestException as e:
        print(f"  [!] Request error for {cve_id}: {e}")
        return _empty_enrichment(cve_id, reason="request_error")


def _parse_nvd_response(cve_id: str, cve_item: dict) -> dict:
    """Extract CVSS v3.1 metrics from NVD API response."""
    metrics    = cve_item.get("metrics", {})
    weaknesses = cve_item.get("weaknesses", [])

    # Extract CWE
    cwe = None
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            if desc.get("lang") == "en":
                cwe = desc.get("value")
                break

    # Try CVSS v3.1 first, fall back to v3.0
    cvss_v3 = None
    cvss_score    = None
    cvss_severity = None
    cvss_vector   = None

    for version_key in ["cvssMetricV31", "cvssMetricV30"]:
        metrics_list = metrics.get(version_key, [])
        if metrics_list:
            cvss_v3       = metrics_list[0].get("cvssData", {})
            cvss_score    = cvss_v3.get("baseScore")
            cvss_severity = cvss_v3.get("baseSeverity")
            cvss_vector   = cvss_v3.get("vectorString")
            break

    return {
        "cve_id":          cve_id,
        "cvss_v3_score":   cvss_score,
        "cvss_v3_severity": cvss_severity,
        "cvss_v3_vector":  cvss_vector,
        "cwe":             cwe,
        "epss_score":      None,
        "epss_percentile": None,
        "has_exploit":     False,
        "enriched":        True,
        "source":          "nvd",
    }


def _empty_enrichment(cve_id: str, reason: str = "unknown") -> dict:
    return {
        "cve_id":          cve_id,
        "cvss_v3_score":   None,
        "cvss_v3_severity": None,
        "cvss_v3_vector":  None,
        "cwe":             None,
        "epss_score":      None,
        "epss_percentile": None,
        "has_exploit":     False,
        "enriched":        False,
        "source":          "nvd",
        "skip_reason":     reason,
    }
