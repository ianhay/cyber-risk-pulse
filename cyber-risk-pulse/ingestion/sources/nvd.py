"""NIST NVD CVE API 2.0 adapter.

Responsibilities:
  * parse NVD API 2.0 payloads into canonical :class:`Vulnerability` records;
  * select a single CVSS metric, preferring the newest version and primary
    source, while recording which version it is;
  * extract vendor/product tokens from CPE match criteria (raw, unnormalised);
  * exclude rejected CVEs;
  * page through results with ``startIndex`` / ``resultsPerPage``;
  * fetch incremental windows using ``lastModStartDate`` / ``lastModEndDate``
    (never spanning more than 120 days per request);
  * enrich a specific set of CVE ids in batches (for KEV CVEs outside the
    rolling window).

Network calls are thin wrappers around parsing so the parsing is fully
testable from fixtures without a network.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from ..http import HttpClient
from ..models import CvssMetric, Reference, Vulnerability

# Preference order (newest / most expressive first).
_CVSS_KEYS = [
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
]


def _english_description(descriptions: list[dict[str, Any]]) -> str:
    for d in descriptions:
        if d.get("lang") == "en":
            return str(d.get("value", "")).strip()
    return str(descriptions[0].get("value", "")).strip() if descriptions else ""


def _is_rejected(cve: dict[str, Any]) -> bool:
    status = str(cve.get("vulnStatus", "")).strip().lower()
    if status == "rejected":
        return True
    desc = _english_description(cve.get("descriptions", []))
    return desc.startswith("** REJECT")


def _select_cvss(metrics: dict[str, Any]) -> CvssMetric | None:
    """Pick the best available CVSS metric, preferring Primary source."""
    for key, version in _CVSS_KEYS:
        candidates = metrics.get(key)
        if not candidates:
            continue
        chosen = None
        for m in candidates:
            if str(m.get("type", "")).lower() == "primary":
                chosen = m
                break
        if chosen is None:
            chosen = candidates[0]
        data = chosen.get("cvssData", {})
        # For CVSS v2 the severity sits on the metric, not on cvssData.
        severity = data.get("baseSeverity") or chosen.get("baseSeverity")
        return CvssMetric(
            version=str(data.get("version", version)),
            base_score=_as_float(data.get("baseScore")),
            severity=str(severity).upper() if severity else None,
            vector=data.get("vectorString"),
            source=chosen.get("source"),
        )
    return None


def _extract_cpe(cve: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    vendors: list[str] = []
    products: list[str] = []
    criteria_list: list[str] = []
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                criteria = match.get("criteria")
                if not criteria:
                    continue
                criteria_list.append(criteria)
                parts = criteria.split(":")
                # cpe:2.3:part:vendor:product:...
                if len(parts) >= 5:
                    vendor, product = parts[3], parts[4]
                    if vendor not in ("*", "-", ""):
                        vendors.append(vendor)
                    if product not in ("*", "-", ""):
                        products.append(product)
    return _dedupe(vendors), _dedupe(products), _dedupe(criteria_list)


def _extract_cwes(cve: dict[str, Any]) -> list[str]:
    cwes: list[str] = []
    for weakness in cve.get("weaknesses", []) or []:
        for desc in weakness.get("description", []) or []:
            value = str(desc.get("value", "")).strip()
            if value.startswith("CWE-"):
                cwes.append(value)
    return _dedupe(cwes)


def parse_nvd_cve(item: dict[str, Any]) -> Vulnerability | None:
    """Parse a single ``vulnerabilities[]`` element. Returns None if rejected."""
    cve = item.get("cve", item)
    if _is_rejected(cve):
        return None
    vendors, products, cpe_matches = _extract_cpe(cve)
    return Vulnerability(
        cve_id=cve["id"],
        description=_english_description(cve.get("descriptions", [])),
        published_at=_parse_dt(cve.get("published")),
        last_modified_at=_parse_dt(cve.get("lastModified")),
        nvd_status=cve.get("vulnStatus"),
        vendor_names=vendors,
        product_names=products,
        cpe_matches=cpe_matches,
        cwes=_extract_cwes(cve),
        cvss=_select_cvss(cve.get("metrics", {}) or {}),
        references=[
            Reference(url=r["url"], source=r.get("source"))
            for r in (cve.get("references", []) or [])
            if r.get("url")
        ],
    )


def parse_nvd_page(payload: dict[str, Any]) -> list[Vulnerability]:
    """Parse a full NVD API 2.0 page, excluding rejected records."""
    out: list[Vulnerability] = []
    for item in payload.get("vulnerabilities", []) or []:
        parsed = parse_nvd_cve(item)
        if parsed is not None:
            out.append(parsed)
    return out


# --- live fetch helpers -----------------------------------------------------


def fetch_recent(
    client: HttpClient,
    base_url: str,
    *,
    window_days: int,
    results_per_page: int,
    delay: float,
    api_key: str | None,
    now: datetime | None = None,
) -> list[Vulnerability]:
    """Fetch CVEs modified within the rolling window, paging and chunking the
    date range so no single request exceeds 120 days."""
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(days=window_days)
    headers = {"apiKey": api_key} if api_key else {}
    results: dict[str, Vulnerability] = {}

    for chunk_start, chunk_end in _date_chunks(start, now, max_days=120):
        offset = 0
        while True:
            params = {
                "lastModStartDate": _fmt(chunk_start),
                "lastModEndDate": _fmt(chunk_end),
                "startIndex": offset,
                "resultsPerPage": results_per_page,
            }
            payload = client.get_json(base_url, params=params, headers=headers, delay=delay)
            for vuln in parse_nvd_page(payload):
                results[vuln.cve_id] = vuln
            total = int(payload.get("totalResults", 0))
            offset += int(payload.get("resultsPerPage", results_per_page))
            if offset >= total or not payload.get("vulnerabilities"):
                break
    return list(results.values())


def enrich_cve_ids(
    client: HttpClient,
    base_url: str,
    cve_ids: Iterable[str],
    *,
    delay: float,
    api_key: str | None,
) -> list[Vulnerability]:
    """Fetch specific CVE ids one per request (the API takes a single cveId).

    Used for KEV CVEs that fall outside the rolling modification window.
    """
    headers = {"apiKey": api_key} if api_key else {}
    out: list[Vulnerability] = []
    for cve_id in cve_ids:
        payload = client.get_json(
            base_url, params={"cveId": cve_id}, headers=headers, delay=delay
        )
        out.extend(parse_nvd_page(payload))
    return out


# --- small utilities --------------------------------------------------------


def _date_chunks(
    start: datetime, end: datetime, max_days: int
) -> list[tuple[datetime, datetime]]:
    chunks: list[tuple[datetime, datetime]] = []
    cursor = start
    step = timedelta(days=max_days)
    while cursor < end:
        chunk_end = min(cursor + step, end)
        chunks.append((cursor, chunk_end))
        cursor = chunk_end
    return chunks or [(start, end)]


def _fmt(dt: datetime) -> str:
    # NVD expects ISO 8601; milliseconds and offset are accepted.
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"):
        try:
            dt = datetime.strptime(text[:26], fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _dedupe(items: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for i in items:
        seen.setdefault(i, None)
    return list(seen.keys())
