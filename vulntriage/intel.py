"""Threat-intelligence enrichment: EPSS (FIRST) and CISA KEV.

EPSS: probability a CVE is exploited in the wild in the next 30 days.
KEV:  CISA's catalog of vulnerabilities known to be actively exploited.

Live mode calls the public APIs and caches results for 24 hours.
Offline mode reads the sample files, so the pipeline runs anywhere.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import requests

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_DIR = Path(".cache")
CACHE_TTL_SECONDS = 24 * 3600


def _cached(name: str, fetch):
    CACHE_DIR.mkdir(exist_ok=True)
    path = CACHE_DIR / name
    if path.exists() and time.time() - path.stat().st_mtime < CACHE_TTL_SECONDS:
        return json.loads(path.read_text())
    data = fetch()
    path.write_text(json.dumps(data))
    return data


def fetch_kev(offline_file: str | None = None) -> set[str]:
    if offline_file:
        data = json.loads(Path(offline_file).read_text())
    else:
        data = _cached("kev.json", lambda: requests.get(KEV_URL, timeout=30).json())
    return {v["cveID"] for v in data.get("vulnerabilities", [])}


def fetch_epss(cves: list[str], offline_file: str | None = None) -> dict[str, tuple[float, float]]:
    """Return {cve: (epss, percentile)}."""
    rows: list[dict] = []
    if offline_file:
        rows = json.loads(Path(offline_file).read_text()).get("data", [])
    else:
        unique = sorted({c for c in cves if c.startswith("CVE-")})
        for i in range(0, len(unique), 100):  # the API accepts a comma-separated batch
            batch = unique[i : i + 100]
            key = "epss-" + hashlib.sha256(",".join(batch).encode()).hexdigest()[:12] + ".json"
            resp = _cached(
                key,
                lambda b=batch: requests.get(EPSS_URL, params={"cve": ",".join(b)}, timeout=30).json(),
            )
            rows.extend(resp.get("data", []))
    return {r["cve"]: (float(r["epss"]), float(r["percentile"])) for r in rows}


def enrich(findings, offline_dir: str | None = None) -> None:
    """Add EPSS and KEV data to vulnerability findings, in place."""
    vulns = [f for f in findings if f.kind == "vulnerability"]
    if not vulns:
        return
    epss_file = kev_file = None
    if offline_dir:
        epss_file = str(Path(offline_dir) / "epss-sample.json")
        kev_file = str(Path(offline_dir) / "kev-sample.json")
    kev = fetch_kev(kev_file)
    epss = fetch_epss([f.rule_id for f in vulns], epss_file)
    for f in vulns:
        f.kev = f.rule_id in kev
        if f.rule_id in epss:
            f.epss, f.epss_percentile = epss[f.rule_id]
