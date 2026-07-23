"""Canonical data models.

These Pydantic models are the single joined representation that the whole
pipeline agrees on. Source adapters return these types (or the sub-models);
prioritisation, validation and output generation consume them. Geometry of
the upstream payloads never leaks past the adapters.
"""
from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator

CVE_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,}$"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CvssMetric(BaseModel):
    """A single CVSS metric. ``version`` records which generation it is so the
    dashboard never silently compares a v2 score against a v3.1 score."""

    version: str  # "4.0" | "3.1" | "3.0" | "2.0"
    base_score: float | None = None
    severity: str | None = None  # CRITICAL | HIGH | MEDIUM | LOW | NONE
    vector: str | None = None
    source: str | None = None


class EpssScore(BaseModel):
    """EPSS probability and percentile as decimals in [0, 1]. Missing data is
    represented by ``None`` values, never zero."""

    probability: float | None = None
    percentile: float | None = None
    score_date: str | None = None  # ISO date string


class KevInfo(BaseModel):
    """CISA KEV catalogue membership and the fields it carries."""

    is_kev: bool = False
    vendor_project: str | None = None
    product: str | None = None
    vulnerability_name: str | None = None
    date_added: str | None = None  # ISO date
    due_date: str | None = None  # ISO date
    required_action: str | None = None
    known_ransomware_campaign_use: str | None = None  # Known | Unknown
    notes: str | None = None


class PriorityInfo(BaseModel):
    """Assigned tier plus the plain-language reasons it was assigned."""

    tier: str = "P4"  # P1 | P2 | P3 | P4
    reasons: list[str] = Field(default_factory=list)


class Reference(BaseModel):
    url: str
    source: str | None = None


class Vulnerability(BaseModel):
    """The canonical joined vulnerability record."""

    cve_id: str
    description: str = ""
    published_at: datetime | None = None
    last_modified_at: datetime | None = None
    nvd_status: str | None = None

    vendor_names: list[str] = Field(default_factory=list)
    product_names: list[str] = Field(default_factory=list)
    cpe_matches: list[str] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)

    cvss: CvssMetric | None = None
    epss: EpssScore | None = None
    kev: KevInfo = Field(default_factory=KevInfo)
    priority: PriorityInfo = Field(default_factory=PriorityInfo)

    references: list[Reference] = Field(default_factory=list)
    data_quality_flags: list[str] = Field(default_factory=list)
    ingested_at: datetime = Field(default_factory=_utcnow)

    @field_validator("cve_id")
    @classmethod
    def _valid_cve(cls, v: str) -> str:
        import re

        if not re.match(CVE_PATTERN, v):
            raise ValueError(f"Invalid CVE identifier: {v!r}")
        return v


class SourceStatus(BaseModel):
    """Health record for a single upstream source in a given run."""

    source: str
    ok: bool
    record_count: int = 0
    fetched_at: datetime | None = None
    used_last_known_good: bool = False
    message: str | None = None


class RunMetadata(BaseModel):
    """Metadata describing an ingestion run, surfaced in the status view."""

    generated_at: datetime = Field(default_factory=_utcnow)
    app_version: str = "0.1.0"
    build_commit: str | None = None
    fixture_mode: bool = False
    sources: list[SourceStatus] = Field(default_factory=list)

    @property
    def overall_status(self) -> str:
        """Current | Degraded | Stale, derived from source health."""
        if any(s.used_last_known_good and not s.ok for s in self.sources):
            return "Stale"
        if any(not s.ok for s in self.sources) or any(
            s.used_last_known_good for s in self.sources
        ):
            return "Degraded"
        return "Current"
