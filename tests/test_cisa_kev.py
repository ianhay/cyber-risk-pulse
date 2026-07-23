from ingestion.sources import cisa_kev


def test_parses_kev_entries(kev_payload):
    result = cisa_kev.parse_kev_catalog(kev_payload)
    assert result.catalog_version == "2026.07.23"
    assert "CVE-2026-10001" in result.entries
    entry = result.entries["CVE-2026-10001"]
    assert entry.is_kev is True
    assert entry.vendor_project == "Microsoft"
    assert entry.due_date == "2026-08-08"


def test_unknown_ransomware_is_not_rewritten(kev_payload):
    result = cisa_kev.parse_kev_catalog(kev_payload)
    assert result.entries["CVE-2026-10002"].known_ransomware_campaign_use == "Unknown"
    assert result.entries["CVE-2026-10001"].known_ransomware_campaign_use == "Known"


def test_rows_without_valid_cve_are_dropped():
    payload = {"vulnerabilities": [
        {"cveID": "NOT-A-CVE", "vendorProject": "x", "product": "y"},
        {"cveID": "CVE-2026-11111", "vendorProject": "ok", "product": "z"},
    ]}
    result = cisa_kev.parse_kev_catalog(payload)
    assert list(result.entries) == ["CVE-2026-11111"]


def test_duplicate_cve_is_deduplicated():
    payload = {"vulnerabilities": [
        {"cveID": "CVE-2026-11111", "product": "a"},
        {"cveID": "CVE-2026-11111", "product": "b"},
    ]}
    result = cisa_kev.parse_kev_catalog(payload)
    assert len(result.entries) == 1
    assert result.entries["CVE-2026-11111"].product == "b"


def test_missing_vulnerabilities_key_raises():
    import pytest

    with pytest.raises(ValueError):
        cisa_kev.parse_kev_catalog({"title": "no list here"})
