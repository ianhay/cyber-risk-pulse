from datetime import datetime, timezone
from pathlib import Path

from ingestion.cli import join_records
from ingestion.config import load_config
from ingestion.history import append_daily_row, read_history
from ingestion.models import RunMetadata, SourceStatus
from ingestion.outputs import build_outputs, daily_history_row, write_outputs
from ingestion.priority import PriorityEngine
from ingestion.sources import cisa_kev, epss, nvd
from ingestion.validation import check_records, guard_against_regression

NOW = datetime(2026, 7, 23, 13, 0, 0, tzinfo=timezone.utc)


def _records(kev_payload, nvd_payload, epss_payload):
    kev = cisa_kev.parse_kev_catalog(kev_payload).entries
    nvd_records = {v.cve_id: v for v in nvd.parse_nvd_page(nvd_payload)}
    epss_scores = epss.parse_epss_response(epss_payload)
    records = join_records(kev, nvd_records, epss_scores)
    engine = PriorityEngine(load_config().priority)
    for v in records:
        v.priority = engine.assign(v, now=NOW)
    return records


def _metadata():
    return RunMetadata(
        generated_at=NOW,
        fixture_mode=True,
        sources=[SourceStatus(source="cisa_kev", ok=True, record_count=4, fetched_at=NOW)],
    )


def test_build_outputs_has_all_files(kev_payload, nvd_payload, epss_payload):
    outputs = build_outputs(_records(kev_payload, nvd_payload, epss_payload), _metadata(), load_config(), now=NOW)
    for name in [
        "current_vulnerabilities.json", "priority_queue.json", "summary.json",
        "vendor_summary.json", "timeseries.json", "methodology.json",
        "status.json", "source_metadata.json",
    ]:
        assert name in outputs


def test_priority_queue_is_p1_first(kev_payload, nvd_payload, epss_payload):
    outputs = build_outputs(_records(kev_payload, nvd_payload, epss_payload), _metadata(), load_config(), now=NOW)
    tiers = [r["tier"] for r in outputs["priority_queue.json"]]
    assert tiers[0] == "P1"
    ranks = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    assert ranks_sorted(tiers, ranks)


def ranks_sorted(tiers, ranks):
    values = [ranks[t] for t in tiers]
    return values == sorted(values)


def test_vendor_normalisation_applied(kev_payload, nvd_payload, epss_payload):
    outputs = build_outputs(_records(kev_payload, nvd_payload, epss_payload), _metadata(), load_config(), now=NOW)
    vendors = {v["vendor"] for v in outputs["vendor_summary.json"]["top_by_total"]}
    # Raw token 'microsoft' should be normalised to 'Microsoft'.
    assert "Microsoft" in vendors


def test_missing_metrics_serialise_as_null(kev_payload, nvd_payload, epss_payload):
    outputs = build_outputs(_records(kev_payload, nvd_payload, epss_payload), _metadata(), load_config(), now=NOW)
    rec = next(r for r in outputs["current_vulnerabilities.json"] if r["id"] == "CVE-2026-10010")
    assert rec["cvss"] is None
    assert rec["epss"] is None


def test_check_records_flags_duplicate(kev_payload, nvd_payload, epss_payload):
    records = _records(kev_payload, nvd_payload, epss_payload)
    records.append(records[0])  # duplicate
    report = check_records(records)
    assert not report.ok
    assert any("Duplicate" in e for e in report.errors)


def test_regression_guard_trips_on_collapse():
    report = guard_against_regression(new_count=10, previous_count=100, max_decline_fraction=0.5)
    assert not report.ok


def test_regression_guard_allows_growth():
    report = guard_against_regression(new_count=120, previous_count=100, max_decline_fraction=0.5)
    assert report.ok


def test_non_empty_output_required():
    report = check_records([])
    assert not report.ok


def test_write_and_history(tmp_path: Path, kev_payload, nvd_payload, epss_payload):
    outputs = build_outputs(_records(kev_payload, nvd_payload, epss_payload), _metadata(), load_config(), now=NOW)
    write_outputs(outputs, tmp_path)
    assert (tmp_path / "summary.json").exists()

    hist = tmp_path / "history.csv"
    append_daily_row(hist, daily_history_row(outputs, _metadata()), run_date=NOW.date())
    # A same-day re-run must not add a second row.
    append_daily_row(hist, daily_history_row(outputs, _metadata()), run_date=NOW.date())
    rows = read_history(hist)
    assert len(rows) == 1
    assert int(rows[0]["p1"]) >= 1
