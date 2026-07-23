from ingestion.cli import join_records
from ingestion.sources import cisa_kev, epss, nvd


def _load(kev_payload, nvd_payload, epss_payload):
    kev = cisa_kev.parse_kev_catalog(kev_payload).entries
    nvd_records = {v.cve_id: v for v in nvd.parse_nvd_page(nvd_payload)}
    epss_scores = epss.parse_epss_response(epss_payload)
    return kev, nvd_records, epss_scores


def test_kev_info_merged_into_nvd_record(kev_payload, nvd_payload, epss_payload):
    kev, nvd_records, epss_scores = _load(kev_payload, nvd_payload, epss_payload)
    merged = {v.cve_id: v for v in join_records(kev, nvd_records, epss_scores)}
    rec = merged["CVE-2026-10001"]
    assert rec.kev.is_kev is True
    assert rec.cvss is not None  # came from NVD
    assert rec.epss is not None  # came from EPSS


def test_kev_only_cve_is_synthesised(kev_payload, nvd_payload, epss_payload):
    kev, nvd_records, epss_scores = _load(kev_payload, nvd_payload, epss_payload)
    merged = {v.cve_id: v for v in join_records(kev, nvd_records, epss_scores)}
    # 9001 is KEV-only (no NVD record) -> must still exist.
    assert "CVE-2025-9001" in merged
    rec = merged["CVE-2025-9001"]
    assert rec.kev.is_kev is True
    assert "no_nvd_record" in rec.data_quality_flags


def test_missing_epss_flagged(kev_payload, nvd_payload, epss_payload):
    kev, nvd_records, epss_scores = _load(kev_payload, nvd_payload, epss_payload)
    merged = {v.cve_id: v for v in join_records(kev, nvd_records, epss_scores)}
    rec = merged["CVE-2026-10010"]
    assert rec.epss is None
    assert "no_epss" in rec.data_quality_flags
    assert "no_cvss" in rec.data_quality_flags


def test_no_duplicate_cve_ids(kev_payload, nvd_payload, epss_payload):
    kev, nvd_records, epss_scores = _load(kev_payload, nvd_payload, epss_payload)
    records = join_records(kev, nvd_records, epss_scores)
    ids = [r.cve_id for r in records]
    assert len(ids) == len(set(ids))
