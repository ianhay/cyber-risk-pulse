from ingestion.sources import epss


def test_parse_epss(epss_payload):
    scores = epss.parse_epss_response(epss_payload)
    assert "CVE-2026-10001" in scores
    s = scores["CVE-2026-10001"]
    assert 0 <= s.probability <= 1
    assert 0 <= s.percentile <= 1
    assert s.score_date == "2026-07-23"


def test_missing_cve_absent_not_zero(epss_payload):
    scores = epss.parse_epss_response(epss_payload)
    # 10010 is deliberately not in the EPSS fixture -> must be absent, not 0.
    assert "CVE-2026-10010" not in scores


def test_out_of_range_becomes_none():
    payload = {"data": [{"cve": "CVE-2026-33333", "epss": "1.7", "percentile": "-0.2", "date": "2026-07-23"}]}
    scores = epss.parse_epss_response(payload)
    assert scores["CVE-2026-33333"].probability is None
    assert scores["CVE-2026-33333"].percentile is None


def test_batching_via_fake_client(epss_payload):
    rows = epss_payload["data"]

    class FakeClient:
        def __init__(self):
            self.batches = []

        def get_json(self, url, params=None, delay=None):
            ids = params["cve"].split(",")
            self.batches.append(len(ids))
            data = [r for r in rows if r["cve"] in ids]
            return {"data": data}

    client = FakeClient()
    ids = [r["cve"] for r in rows]
    scores = epss.fetch_epss(client, "http://x", ids, batch_size=3)
    assert max(client.batches) <= 3
    assert len(scores) == len(ids)


def test_malformed_payload_raises():
    import pytest

    with pytest.raises(ValueError):
        epss.parse_epss_response({"status": "OK"})
