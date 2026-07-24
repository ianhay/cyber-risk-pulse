"""Output validation and sanity checks.

Two jobs:
  * ``check_records`` applies per-record sanity rules and returns a list of
    problems (errors) and warnings without mutating the data.
  * ``guard_against_regression`` compares a candidate output against the
    previously deployed output and refuses a suspicious collapse in record
    count, which is the core of last-known-good protection.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import Vulnerability

CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


@dataclass
class ValidationReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def check_records(records: list[Vulnerability]) -> ValidationReport:
    report = ValidationReport()
    if not records:
        report.errors.append("Output contains zero vulnerability records")
        return report

    seen: set[str] = set()
    for v in records:
        if not CVE_RE.match(v.cve_id):
            report.errors.append(f"Invalid CVE id: {v.cve_id}")
        if v.cve_id in seen:
            report.errors.append(f"Duplicate CVE id: {v.cve_id}")
        seen.add(v.cve_id)

        if v.cvss and v.cvss.base_score is not None and not (0 <= v.cvss.base_score <= 10):
            report.errors.append(f"{v.cve_id}: CVSS base score out of range: {v.cvss.base_score}")

        if v.epss:
            for name, val in (("probability", v.epss.probability), ("percentile", v.epss.percentile)):
                if val is not None and not (0 <= val <= 1):
                    report.errors.append(f"{v.cve_id}: EPSS {name} out of range: {val}")

        if v.priority.tier == "P1" and not v.priority.reasons:
            report.errors.append(f"{v.cve_id}: P1 record has no stated reason")

        if v.published_at is None and not v.kev.is_kev:
            report.warnings.append(f"{v.cve_id}: no publication timestamp")

        # KEV date-added earlier than the CVE identifier year is suspicious.
        if v.kev.is_kev and v.kev.date_added:
            year_match = re.match(r"CVE-([0-9]{4})-", v.cve_id)
            if year_match:
                cve_year = int(year_match.group(1))
                added_year = _year_of(v.kev.date_added)
                if added_year is not None and added_year < cve_year:
                    report.warnings.append(
                        f"{v.cve_id}: KEV date-added {v.kev.date_added} precedes CVE year"
                    )
    return report


def guard_against_regression(
    new_count: int, previous_count: int | None, max_decline_fraction: float
) -> ValidationReport:
    """Fail if the new record count falls by more than the allowed fraction."""
    report = ValidationReport()
    if previous_count is None or previous_count == 0:
        return report
    if new_count == 0:
        report.errors.append("New output is empty while previous output was not")
        return report
    decline = (previous_count - new_count) / previous_count
    if decline > max_decline_fraction:
        report.errors.append(
            f"Record count fell {decline:.0%} "
            f"({previous_count} -> {new_count}), exceeding allowed {max_decline_fraction:.0%}"
        )
    return report


def _year_of(date_str: str) -> int | None:
    m = re.match(r"([0-9]{4})", date_str)
    return int(m.group(1)) if m else None
