from datetime import timezone

from ingestion.sources import nvd


def test_parse_page_excludes_rejected(nvd_payload):
    records = nvd.parse_nvd_page(nvd_payload)
    ids = {r.cve_id for r in records}
    assert "CVE-2026-19999" not in ids  # rejected
    assert "CVE-2026-10001" in ids
    # 11 valid rows in the fixture, 1 rejected.
    assert len(records) == 11


def test_cvss_version_selection_prefers_newest(nvd_payload):
    records = {r.cve_id: r for r in nvd.parse_nvd_page(nvd_payload)}
    # 10003 carries a CVSS v4.0 metric.
    assert records["CVE-2026-10003"].cvss.version == "4.0"
    assert records["CVE-2026-10003"].cvss.base_score == 9.1
    # 10001 carries v3.1.
    assert records["CVE-2026-10001"].cvss.version == "3.1"


def test_cvss_v2_severity_read_from_metric():
    payload = {"vulnerabilities": [{"cve": {
        "id": "CVE-2026-22222",
        "vulnStatus": "Analyzed",
        "published": "2026-01-01T00:00:00.000",
        "lastModified": "2026-01-02T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "legacy metric only"}],
        "metrics": {"cvssMetricV2": [{
            "type": "Primary", "baseSeverity": "HIGH",
            "cvssData": {"version": "2.0", "baseScore": 7.5, "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
        }]},
    }}]}
    rec = nvd.parse_nvd_page(payload)[0]
    assert rec.cvss.version == "2.0"
    assert rec.cvss.severity == "HIGH"


def test_cpe_vendor_product_extraction(nvd_payload):
    records = {r.cve_id: r for r in nvd.parse_nvd_page(nvd_payload)}
    rec = records["CVE-2026-10001"]
    assert "microsoft" in rec.vendor_names
    assert "windows_server" in rec.product_names


def test_missing_cvss_is_none(nvd_payload):
    records = {r.cve_id: r for r in nvd.parse_nvd_page(nvd_payload)}
    assert records["CVE-2026-10010"].cvss is None  # never zero


def test_dates_parsed_as_utc(nvd_payload):
    records = {r.cve_id: r for r in nvd.parse_nvd_page(nvd_payload)}
    pub = records["CVE-2026-10001"].published_at
    assert pub is not None
    assert pub.tzinfo == timezone.utc


def test_date_chunks_never_exceed_max():
    from datetime import datetime

    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    end = datetime(2026, 1, 1, tzinfo=timezone.utc)
    chunks = nvd._date_chunks(start, end, max_days=120)
    assert len(chunks) == 4  # 365 days / 120
    for s, e in chunks:
        assert (e - s).days <= 120


def test_pagination_via_fake_client(nvd_payload):
    # Two-page response driven by a fake client verifies offset paging.
    page1 = {"totalResults": 4, "resultsPerPage": 2, "vulnerabilities": nvd_payload["vulnerabilities"][:2]}
    page2 = {"totalResults": 4, "resultsPerPage": 2, "vulnerabilities": nvd_payload["vulnerabilities"][2:4]}

    class FakeClient:
        def __init__(self):
            self.calls = 0

        def get_json(self, url, params=None, headers=None, delay=None):
            self.calls += 1
            return page1 if params["startIndex"] == 0 else page2

    client = FakeClient()
    out = nvd.fetch_recent(
        client, "http://x", window_days=30, results_per_page=2, delay=0, api_key=None,
    )
    assert client.calls == 2
    assert len(out) >= 3
