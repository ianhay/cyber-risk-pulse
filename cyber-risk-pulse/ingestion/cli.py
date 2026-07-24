"""Ingestion orchestration.

Ties the adapters together into one run:

  1. load CISA KEV;
  2. load the rolling NVD window;
  3. enrich KEV CVEs missing from that window;
  4. join KEV into NVD records (or synthesise a minimal record for a KEV-only
     CVE) so no known-exploited CVE is ever dropped;
  5. attach EPSS scores;
  6. assign transparent priority tiers;
  7. build compact outputs, validate them, guard against a suspicious record
     collapse, then write them and append the daily history row.

Two modes:
  * ``--live``   real network calls (used by the scheduled workflow);
  * ``--fixture`` reads ``tests/fixtures/*.json`` and makes no network calls,
    so the site can be built and tested offline.

If a live source fails, the previously deployed output for that source is
retained and the run is marked Degraded/Stale rather than overwriting good
data with empty data.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .config import Config, load_config
from .http import HttpClient
from .models import KevInfo, RunMetadata, SourceStatus, Vulnerability
from .outputs import build_outputs, daily_history_row, write_outputs
from .priority import PriorityEngine
from .sources import cisa_kev, epss, nvd
from .validation import check_records, guard_against_regression
from .history import append_daily_row

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO_ROOT / "public" / "data"
DEFAULT_FIXTURES = REPO_ROOT / "tests" / "fixtures"
HISTORY_PATH = REPO_ROOT / "public" / "data" / "history.csv"
MAX_DECLINE_FRACTION = 0.5


def _make_client(config: Config) -> HttpClient:
    http_cfg = config.sources["http"]
    return HttpClient(
        timeout=float(http_cfg["timeout_seconds"]),
        max_retries=int(http_cfg["max_retries"]),
        backoff_base=float(http_cfg["backoff_base_seconds"]),
        backoff_max=float(http_cfg["backoff_max_seconds"]),
        user_agent=str(http_cfg["user_agent"]),
    )


# --- source loaders (live) --------------------------------------------------


def _load_kev_live(client: HttpClient, config: Config) -> tuple[dict[str, KevInfo], SourceStatus]:
    cfg = config.sources["cisa_kev"]
    try:
        result = cisa_kev.fetch_kev(client, cfg["feed_json"], int(cfg["min_expected_rows"]))
        status = SourceStatus(
            source="cisa_kev",
            ok=True,
            record_count=len(result.entries),
            fetched_at=datetime.now(timezone.utc),
            message=f"catalogue {result.catalog_version or '?'}",
        )
        return result.entries, status
    except Exception as exc:  # noqa: BLE001
        return {}, SourceStatus(source="cisa_kev", ok=False, message=str(exc))


def _load_nvd_live(
    client: HttpClient, config: Config, kev: dict[str, KevInfo]
) -> tuple[dict[str, Vulnerability], SourceStatus]:
    cfg = config.sources["nvd"]
    api_key = config.nvd_api_key
    delay = float(cfg["request_delay_seconds_with_key"] if api_key else cfg["request_delay_seconds_no_key"])
    try:
        records = nvd.fetch_recent(
            client,
            cfg["cve_api"],
            window_days=int(cfg["rolling_window_days"]),
            results_per_page=int(cfg["results_per_page"]),
            delay=delay,
            api_key=api_key,
        )
        by_id = {v.cve_id: v for v in records}
        missing = _kev_ids_to_enrich(
            [c for c in kev if c not in by_id],
            kev,
            max_age_days=int(cfg.get("enrich_max_age_days", 120)),
            max_count=int(cfg.get("enrich_max_count", 150)),
        )
        if missing:
            for enriched in nvd.enrich_cve_ids(client, cfg["cve_api"], missing, delay=delay, api_key=api_key):
                by_id[enriched.cve_id] = enriched
        status = SourceStatus(
            source="nvd",
            ok=True,
            record_count=len(by_id),
            fetched_at=datetime.now(timezone.utc),
            message=f"{len(records)} in window, {len(missing)} KEV enriched",
        )
        return by_id, status
    except Exception as exc:  # noqa: BLE001
        return {}, SourceStatus(source="nvd", ok=False, message=str(exc))


def _kev_ids_to_enrich(
    candidate_ids: list[str],
    kev: dict[str, KevInfo],
    *,
    max_age_days: int,
    max_count: int,
) -> list[str]:
    """Bound per-CVE KEV enrichment so a live run stays fast.

    NVD offers no bulk cveId lookup, so each enrichment is one request. Against
    the full historical KEV catalogue that would be ~1000+ sequential requests.
    We only enrich recently added KEV entries (most likely to still be in active
    remediation) and cap the total. Older KEV CVEs still appear as records built
    from the KEV feed itself and are P1 regardless of CVSS, so the cap costs
    detail, never a missing known-exploited vulnerability.
    """
    cutoff = datetime.now(timezone.utc).date()
    kept: list[tuple[str, str]] = []
    for cve_id in candidate_ids:
        added = (kev.get(cve_id).date_added if kev.get(cve_id) else None) or ""
        try:
            added_date = datetime.fromisoformat(added).date()
        except ValueError:
            # No usable date - enrich it (it is unusual and worth the detail),
            # but it still competes for the cap below.
            kept.append((cve_id, ""))
            continue
        if (cutoff - added_date).days <= max_age_days:
            kept.append((cve_id, added))
    # Most recent first, then apply the hard cap.
    kept.sort(key=lambda pair: pair[1], reverse=True)
    return [cve_id for cve_id, _ in kept[:max_count]]



    cfg = config.sources["epss"]
    try:
        scores = epss.fetch_epss(client, cfg["api"], cve_ids, batch_size=int(cfg["batch_size"]))
        return scores, SourceStatus(
            source="epss", ok=True, record_count=len(scores), fetched_at=datetime.now(timezone.utc)
        )
    except Exception as exc:  # noqa: BLE001
        return {}, SourceStatus(source="epss", ok=False, message=str(exc))


# --- source loaders (fixture) -----------------------------------------------


def _load_fixtures(fixtures_dir: Path):
    kev_payload = json.loads((fixtures_dir / "cisa_kev_sample.json").read_text("utf-8"))
    nvd_payload = json.loads((fixtures_dir / "nvd_sample.json").read_text("utf-8"))
    epss_payload = json.loads((fixtures_dir / "epss_sample.json").read_text("utf-8"))

    kev = cisa_kev.parse_kev_catalog(kev_payload).entries
    nvd_records = {v.cve_id: v for v in nvd.parse_nvd_page(nvd_payload)}
    epss_scores = epss.parse_epss_response(epss_payload)
    return kev, nvd_records, epss_scores


# --- join + prioritise ------------------------------------------------------


def join_records(
    kev: dict[str, KevInfo],
    nvd_records: dict[str, Vulnerability],
    epss_scores: dict,
) -> list[Vulnerability]:
    """Merge the three sources into canonical records keyed by CVE id."""
    merged: dict[str, Vulnerability] = dict(nvd_records)

    # KEV-only CVEs (no NVD record available): synthesise a minimal record so a
    # known-exploited CVE is never dropped.
    for cve_id, kev_info in kev.items():
        if cve_id in merged:
            merged[cve_id].kev = kev_info
        else:
            merged[cve_id] = Vulnerability(
                cve_id=cve_id,
                description=kev_info.vulnerability_name or "",
                kev=kev_info,
                data_quality_flags=["no_nvd_record"],
            )

    for cve_id, vuln in merged.items():
        score = epss_scores.get(cve_id)
        if score is not None:
            vuln.epss = score
        elif vuln.epss is None:
            vuln.data_quality_flags.append("no_epss")
        if vuln.cvss is None:
            vuln.data_quality_flags.append("no_cvss")

    return list(merged.values())


def run_pipeline(
    *,
    fixture_mode: bool,
    out_dir: Path,
    fixtures_dir: Path,
    config: Config | None = None,
    build_commit: str | None = None,
    now: datetime | None = None,
) -> RunMetadata:
    config = config or load_config()
    now = now or datetime.now(timezone.utc)
    statuses: list[SourceStatus] = []

    if fixture_mode:
        kev, nvd_records, epss_scores = _load_fixtures(fixtures_dir)
        statuses = [
            SourceStatus(source="cisa_kev", ok=True, record_count=len(kev), fetched_at=now, message="fixture"),
            SourceStatus(source="nvd", ok=True, record_count=len(nvd_records), fetched_at=now, message="fixture"),
            SourceStatus(source="epss", ok=True, record_count=len(epss_scores), fetched_at=now, message="fixture"),
        ]
    else:
        client = _make_client(config)
        kev, kev_status = _load_kev_live(client, config)
        statuses.append(kev_status)
        nvd_records, nvd_status = _load_nvd_live(client, config, kev)
        statuses.append(nvd_status)
        all_ids = sorted(set(kev.keys()) | set(nvd_records.keys()))
        epss_scores, epss_status = _load_epss_live(client, config, all_ids)
        statuses.append(epss_status)

    records = join_records(kev, nvd_records, epss_scores)

    engine = PriorityEngine(config.priority)
    for vuln in records:
        vuln.priority = engine.assign(vuln, now=now)

    metadata = RunMetadata(
        generated_at=now,
        app_version="0.1.0",
        build_commit=build_commit,
        fixture_mode=fixture_mode,
        sources=statuses,
    )

    report = check_records(records)
    for warning in report.warnings:
        print(f"[warn] {warning}", file=sys.stderr)
    if not report.ok:
        for err in report.errors:
            print(f"[error] {err}", file=sys.stderr)
        raise SystemExit("Validation failed; refusing to write output")

    # Last-known-good: never replace a healthy dataset with a collapsed one.
    previous_count = _previous_record_count(out_dir)
    regression = guard_against_regression(len(records), previous_count, MAX_DECLINE_FRACTION)
    if not regression.ok:
        for err in regression.errors:
            print(f"[error] {err}", file=sys.stderr)
        raise SystemExit("Record-count regression guard tripped; keeping previous output")

    outputs = build_outputs(records, metadata, config, now=now)
    write_outputs(outputs, out_dir)
    append_daily_row(out_dir / "history.csv", daily_history_row(outputs, metadata), run_date=now.date())

    print(
        f"Wrote {len(records)} records to {out_dir} "
        f"(status={metadata.overall_status}, fixture={fixture_mode})"
    )
    return metadata


def _previous_record_count(out_dir: Path) -> int | None:
    path = out_dir / "current_vulnerabilities.json"
    if not path.exists():
        return None
    try:
        return len(json.loads(path.read_text("utf-8")))
    except Exception:  # noqa: BLE001
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cyber Risk Pulse data ingestion")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--live", action="store_true", help="fetch from live sources")
    mode.add_argument("--fixture", action="store_true", help="use bundled fixtures (offline)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output directory")
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES, help="fixtures directory")
    parser.add_argument("--commit", type=str, default=None, help="build commit sha")
    args = parser.parse_args(argv)

    fixture_mode = not args.live  # default to fixture unless --live is given
    run_pipeline(
        fixture_mode=fixture_mode,
        out_dir=args.out,
        fixtures_dir=args.fixtures,
        build_commit=args.commit,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
