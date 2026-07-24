"""Generate compact, dashboard-ready output files from canonical records.

The browser never receives raw NVD responses. It receives:
  * ``current_vulnerabilities.json`` - the canonical trimmed record array that
    the interactive views derive KPIs, charts, the queue and vendor analysis
    from, so every view stays consistent under shared filters;
  * ``status.json`` / ``source_metadata.json`` - freshness and source health;
  * ``summary.json`` / ``vendor_summary.json`` / ``timeseries.json`` /
    ``priority_queue.json`` - server-computed baselines for the methodology and
    status views and as a documented data contract;
  * ``methodology.json`` - the thresholds, labels and rules shown to users.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from .config import Config
from .models import RunMetadata, Vulnerability


class VendorNormaliser:
    def __init__(self, vendor_aliases: dict[str, Any]) -> None:
        self._lookup: dict[str, str] = {}
        for canonical, variants in (vendor_aliases.get("canonical") or {}).items():
            self._lookup[canonical.lower()] = canonical
            for variant in variants or []:
                self._lookup[str(variant).lower()] = canonical

    def display(self, raw: str) -> str:
        """Return a canonical display name, or a tidied raw token if unknown.

        Never invents a vendor: an unknown token is only reformatted
        (underscores -> spaces, title-cased) for readability.
        """
        canonical = self._lookup.get(raw.lower())
        if canonical:
            return canonical
        return raw.replace("_", " ").strip().title()


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _compact_record(v: Vulnerability, norm: VendorNormaliser) -> dict[str, Any]:
    return {
        "id": v.cve_id,
        "desc": v.description,
        "published": _iso(v.published_at),
        "modified": _iso(v.last_modified_at),
        "status": v.nvd_status,
        "vendors": [norm.display(x) for x in v.vendor_names],
        "vendorsRaw": v.vendor_names,
        "products": v.product_names,
        "cwes": v.cwes,
        "cvss": (
            {
                "version": v.cvss.version,
                "score": v.cvss.base_score,
                "severity": v.cvss.severity,
                "vector": v.cvss.vector,
                "source": v.cvss.source,
            }
            if v.cvss
            else None
        ),
        "epss": (
            {"p": v.epss.probability, "pct": v.epss.percentile, "date": v.epss.score_date}
            if v.epss
            else None
        ),
        "kev": (
            {
                "isKev": True,
                "vendorProject": v.kev.vendor_project,
                "product": v.kev.product,
                "name": v.kev.vulnerability_name,
                "dateAdded": v.kev.date_added,
                "dueDate": v.kev.due_date,
                "requiredAction": v.kev.required_action,
                "ransomware": v.kev.known_ransomware_campaign_use,
            }
            if v.kev.is_kev
            else None
        ),
        "tier": v.priority.tier,
        "reasons": v.priority.reasons,
        "refs": [{"url": r.url, "source": r.source} for r in v.references],
        "flags": v.data_quality_flags,
    }


def _severity_bucket(v: Vulnerability) -> str:
    if not v.cvss or v.cvss.base_score is None:
        return "UNKNOWN"
    s = v.cvss.base_score
    if s >= 9.0:
        return "CRITICAL"
    if s >= 7.0:
        return "HIGH"
    if s >= 4.0:
        return "MEDIUM"
    if s > 0:
        return "LOW"
    return "NONE"


def build_outputs(
    records: list[Vulnerability],
    metadata: RunMetadata,
    config: Config,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    norm = VendorNormaliser(config.vendor_aliases)
    dash = config.dashboard
    window_days = int(dash["default_window_days"])
    high_epss = float(dash["thresholds"]["high_epss_probability"])
    crit_cvss = float(dash["thresholds"]["critical_cvss"])

    compact = [_compact_record(v, norm) for v in records]

    tier_counts = Counter(v.priority.tier for v in records)
    sev_counts = Counter(_severity_bucket(v) for v in records)
    kev_count = sum(1 for v in records if v.kev.is_kev)
    high_epss_count = sum(
        1 for v in records if v.epss and v.epss.probability is not None and v.epss.probability >= high_epss
    )
    critical_count = sum(
        1 for v in records if v.cvss and v.cvss.base_score is not None and v.cvss.base_score >= crit_cvss
    )

    def _within_window(dt: datetime | None) -> bool:
        if dt is None:
            return False
        return (now - dt).total_seconds() <= window_days * 86400

    new_cves = sum(1 for v in records if _within_window(v.published_at))
    new_kev = sum(1 for v in records if v.kev.is_kev and _kev_added_within(v, now, window_days))

    # Server-side aggregates.
    summary = {
        "window_days": window_days,
        "generated_at": _iso(metadata.generated_at),
        "kpis": {
            "new_cves": new_cves,
            "new_kev": new_kev,
            "kev_catalogue_total": kev_count,
            "high_epss": high_epss_count,
            "critical": critical_count,
            "p1": tier_counts.get("P1", 0),
            "total_scope": len(records),
        },
        "tier_counts": {t: tier_counts.get(t, 0) for t in dash["priority_order"]},
        "severity_counts": dict(sev_counts),
    }

    vendor_summary = _vendor_summary(records, norm)
    timeseries = _timeseries(records)
    priority_queue = sorted(
        compact,
        key=lambda r: (
            _tier_rank(r["tier"]),
            -(r["epss"]["p"] if r["epss"] and r["epss"]["p"] is not None else -1),
            -((r["cvss"]["score"] if r["cvss"] and r["cvss"]["score"] is not None else -1)),
        ),
    )

    methodology = {
        "terminology": dash["terminology"],
        "statement": dash["methodology_statement"],
        "priority_rules": config.priority["priority_rules"],
        "tier_labels": config.priority["tier_labels"],
        "thresholds": dash["thresholds"],
        "time_windows_days": dash["time_windows_days"],
        "default_window_days": window_days,
        "sources": {
            k: {"name": v.get("name")}
            for k, v in config.sources.items()
            if isinstance(v, dict) and v.get("name")
        },
    }

    status = {
        "overall_status": metadata.overall_status,
        "generated_at": _iso(metadata.generated_at),
        "app_version": metadata.app_version,
        "build_commit": metadata.build_commit,
        "fixture_mode": metadata.fixture_mode,
        "freshness": dash["freshness"],
        "sources": [
            {
                "source": s.source,
                "ok": s.ok,
                "record_count": s.record_count,
                "fetched_at": _iso(s.fetched_at),
                "used_last_known_good": s.used_last_known_good,
                "message": s.message,
            }
            for s in metadata.sources
        ],
    }

    return {
        "current_vulnerabilities.json": compact,
        "priority_queue.json": priority_queue,
        "summary.json": summary,
        "vendor_summary.json": vendor_summary,
        "timeseries.json": timeseries,
        "methodology.json": methodology,
        "status.json": status,
        "source_metadata.json": status["sources"],
    }


def daily_history_row(outputs: dict[str, Any], metadata: RunMetadata) -> dict[str, object]:
    summary = outputs["summary.json"]
    tiers = summary["tier_counts"]
    return {
        "total_scope": summary["kpis"]["total_scope"],
        "new_cves": summary["kpis"]["new_cves"],
        "new_kev": summary["kpis"]["new_kev"],
        "p1": tiers.get("P1", 0),
        "p2": tiers.get("P2", 0),
        "p3": tiers.get("P3", 0),
        "p4": tiers.get("P4", 0),
        "critical": summary["kpis"]["critical"],
        "high_epss": summary["kpis"]["high_epss"],
        "source_status": metadata.overall_status,
    }


def write_outputs(outputs: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, obj in outputs.items():
        with (out_dir / name).open("w", encoding="utf-8") as fh:
            json.dump(obj, fh, ensure_ascii=False, separators=(",", ":"))


# --- aggregation helpers ----------------------------------------------------


def _vendor_summary(records: list[Vulnerability], norm: VendorNormaliser) -> dict[str, Any]:
    total = Counter()
    priority = Counter()
    kev_products = Counter()
    for v in records:
        display_vendors = {norm.display(x) for x in v.vendor_names}
        if v.kev.is_kev and v.kev.vendor_project:
            display_vendors.add(norm.display(v.kev.vendor_project))
        for vendor in display_vendors:
            total[vendor] += 1
            if v.priority.tier in ("P1", "P2"):
                priority[vendor] += 1
        if v.kev.is_kev and v.kev.product:
            kev_products[v.kev.product] += 1
    return {
        "top_by_total": [{"vendor": k, "count": c} for k, c in total.most_common(15)],
        "top_by_priority": [{"vendor": k, "count": c} for k, c in priority.most_common(15)],
        "top_kev_products": [{"product": k, "count": c} for k, c in kev_products.most_common(15)],
    }


def _timeseries(records: list[Vulnerability]) -> dict[str, Any]:
    new_by_day: Counter = Counter()
    kev_by_day: Counter = Counter()
    time_to_kev: list[dict[str, Any]] = []
    for v in records:
        if v.published_at:
            new_by_day[v.published_at.date().isoformat()] += 1
        if v.kev.is_kev and v.kev.date_added:
            kev_by_day[v.kev.date_added[:10]] += 1
            if v.published_at:
                try:
                    added = date.fromisoformat(v.kev.date_added[:10])
                    days = (added - v.published_at.date()).days
                    if days >= 0:
                        time_to_kev.append({"cve": v.cve_id, "days": days})
                except ValueError:
                    pass
    return {
        "new_cves_by_day": [{"date": d, "count": c} for d, c in sorted(new_by_day.items())],
        "new_kev_by_day": [{"date": d, "count": c} for d, c in sorted(kev_by_day.items())],
        "time_to_kev": sorted(time_to_kev, key=lambda x: x["days"]),
    }


def _kev_added_within(v: Vulnerability, now: datetime, window_days: int) -> bool:
    if not v.kev.date_added:
        return False
    try:
        added = date.fromisoformat(v.kev.date_added[:10])
    except ValueError:
        return False
    return (now.date() - added).days <= window_days


def _tier_rank(tier: str) -> int:
    return {"P1": 0, "P2": 1, "P3": 2, "P4": 3}.get(tier, 4)
