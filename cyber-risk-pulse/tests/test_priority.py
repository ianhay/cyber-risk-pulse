from datetime import datetime, timedelta, timezone

from ingestion.config import load_config
from ingestion.models import CvssMetric, EpssScore, KevInfo, Vulnerability
from ingestion.priority import PriorityEngine

NOW = datetime(2026, 7, 23, tzinfo=timezone.utc)


def engine():
    return PriorityEngine(load_config().priority)


def _vuln(**kw):
    base = dict(cve_id="CVE-2026-40000", published_at=NOW - timedelta(days=200))
    base.update(kw)
    return Vulnerability(**base)


def test_kev_forces_p1_even_with_low_scores():
    v = _vuln(kev=KevInfo(is_kev=True), cvss=CvssMetric(version="3.1", base_score=2.0))
    result = engine().assign(v, now=NOW)
    assert result.tier == "P1"
    assert any("KEV" in r for r in result.reasons)


def test_high_epss_and_high_cvss_is_p1():
    v = _vuln(
        cvss=CvssMetric(version="3.1", base_score=9.1),
        epss=EpssScore(probability=0.55, percentile=0.98),
    )
    assert engine().assign(v, now=NOW).tier == "P1"


def test_p2_boundary_epss_and_cvss():
    v = _vuln(
        cvss=CvssMetric(version="3.1", base_score=8.0),
        epss=EpssScore(probability=0.10, percentile=0.5),
    )
    assert engine().assign(v, now=NOW).tier == "P2"


def test_p2_recent_critical():
    v = _vuln(
        cvss=CvssMetric(version="3.1", base_score=9.0),
        epss=EpssScore(probability=0.01, percentile=0.2),
        published_at=NOW - timedelta(days=5),
    )
    assert engine().assign(v, now=NOW).tier == "P2"


def test_p3_by_cvss():
    v = _vuln(cvss=CvssMetric(version="3.1", base_score=7.0))
    assert engine().assign(v, now=NOW).tier == "P3"


def test_p4_default():
    v = _vuln(cvss=CvssMetric(version="3.1", base_score=4.0))
    assert engine().assign(v, now=NOW).tier == "P4"


def test_missing_data_is_not_treated_as_zero():
    # No CVSS and no EPSS -> should fall to P4, never match a threshold as 0.
    v = _vuln(cvss=None, epss=None)
    assert engine().assign(v, now=NOW).tier == "P4"


def test_every_p1_has_a_reason():
    v = _vuln(kev=KevInfo(is_kev=True))
    assert engine().assign(v, now=NOW).reasons
