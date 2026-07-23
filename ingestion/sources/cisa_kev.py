"""CISA Known Exploited Vulnerabilities adapter.

Downloads the full KEV catalogue, validates it, and returns a mapping of
CVE id -> :class:`KevInfo`. KEV membership is the authoritative flag that a
vulnerability has been exploited in the wild and always forces Priority 1.
"""
from __future__ import annotations

import re
from typing import Any

from ..http import HttpClient
from ..models import KevInfo

CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


class CisaKevResult:
    def __init__(
        self,
        entries: dict[str, KevInfo],
        catalog_version: str | None,
        date_released: str | None,
        raw_count: int,
    ) -> None:
        self.entries = entries
        self.catalog_version = catalog_version
        self.date_released = date_released
        self.raw_count = raw_count


def parse_kev_catalog(payload: dict[str, Any]) -> CisaKevResult:
    """Parse a KEV JSON payload into canonical :class:`KevInfo` records.

    Deduplicates on CVE id, requires a valid CVE identifier on every retained
    row, and never rewrites an ``Unknown`` ransomware value to ``No``.
    """
    vulns = payload.get("vulnerabilities")
    if not isinstance(vulns, list):
        raise ValueError("KEV payload missing 'vulnerabilities' list")

    entries: dict[str, KevInfo] = {}
    for row in vulns:
        cve = str(row.get("cveID", "")).strip()
        if not CVE_RE.match(cve):
            # A KEV row without a valid CVE id is not retained.
            continue
        ransomware = row.get("knownRansomwareCampaignUse")
        if isinstance(ransomware, str):
            ransomware = ransomware.strip() or None
        entries[cve] = KevInfo(
            is_kev=True,
            vendor_project=_clean(row.get("vendorProject")),
            product=_clean(row.get("product")),
            vulnerability_name=_clean(row.get("vulnerabilityName")),
            date_added=_clean(row.get("dateAdded")),
            due_date=_clean(row.get("dueDate")),
            required_action=_clean(row.get("requiredAction")),
            known_ransomware_campaign_use=ransomware,
            notes=_clean(row.get("notes")),
        )

    return CisaKevResult(
        entries=entries,
        catalog_version=_clean(payload.get("catalogVersion")),
        date_released=_clean(payload.get("dateReleased")),
        raw_count=len(vulns),
    )


def fetch_kev(client: HttpClient, url: str, min_expected: int) -> CisaKevResult:
    """Fetch and validate the live KEV catalogue."""
    payload = client.get_json(url)
    result = parse_kev_catalog(payload)
    if len(result.entries) < min_expected:
        raise ValueError(
            f"KEV catalogue returned {len(result.entries)} valid rows, "
            f"below minimum {min_expected}"
        )
    return result


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
