import json
import time
from pathlib import Path
import requests

EPSS_API_BASE = "https://api.first.org/data/v1/epss"
CACHE_DIR     = Path("cache/epss")
BATCH_SIZE    = 100
REQUEST_DELAY = 1.0


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


def fetch_epss_batch(cve_ids: list[str]) -> dict[str, dict]:
    """
    Fetch EPSS scores for a list of CVE IDs.
    Returns {cve_id: {"epss_score": float, "epss_percentile": float}}
    Batches requests in groups of BATCH_SIZE.
    """
    results    = {}
    to_fetch   = []

    # Check cache first
    for cve_id in cve_ids:
        cached = _load_cache(cve_id)
        if cached is not None:
            results[cve_id] = cached
        else:
            to_fetch.append(cve_id)

    if not to_fetch:
        return results

    # Batch fetch uncached CVEs
    for i in range(0, len(to_fetch), BATCH_SIZE):
        batch = to_fetch[i:i + BATCH_SIZE]
        batch_results = _fetch_batch(batch)
        results.update(batch_results)
        if i + BATCH_SIZE < len(to_fetch):
            time.sleep(REQUEST_DELAY)

    return results


def _fetch_batch(cve_ids: list[str]) -> dict[str, dict]:
    """Fetch a single batch of up to 100 CVE IDs from EPSS API."""
    try:
        response = requests.get(
            EPSS_API_BASE,
            params={"cve": ",".join(cve_ids)},
            timeout=15,
        )

        if response.status_code != 200:
            print(f"  [!] EPSS API returned {response.status_code}")
            return {cve: _empty_epss(cve) for cve in cve_ids}

        data = response.json()
        epss_data = {
            item["cve"]: {
                "epss_score":      float(item.get("epss", 0.0)),
                "epss_percentile": float(item.get("percentile", 0.0)),
            }
            for item in data.get("data", [])
        }

        # Fill in missing CVEs with empty records
        results = {}
        for cve_id in cve_ids:
            if cve_id in epss_data:
                result = epss_data[cve_id]
                _save_cache(cve_id, result)
            else:
                result = _empty_epss(cve_id)
                _save_cache(cve_id, result)
            results[cve_id] = result

        return results

    except requests.exceptions.RequestException as e:
        print(f"  [!] EPSS request error: {e}")
        return {cve: _empty_epss(cve) for cve in cve_ids}


def _empty_epss(cve_id: str) -> dict:
    return {
        "epss_score":      None,
        "epss_percentile": None,
    }
