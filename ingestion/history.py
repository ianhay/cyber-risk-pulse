"""Compact daily history.

Appends one aggregate row per calendar day to a CSV so the dashboard can show
trends without committing full source snapshots. A same-day re-run replaces the
existing row for that date rather than adding a duplicate, keeping growth to at
most one row per day.
"""
from __future__ import annotations

import csv
from datetime import date
from pathlib import Path

HISTORY_FIELDS = [
    "date",
    "total_scope",
    "new_cves",
    "new_kev",
    "p1",
    "p2",
    "p3",
    "p4",
    "critical",
    "high_epss",
    "source_status",
]


def append_daily_row(path: Path, row: dict[str, object], run_date: date | None = None) -> None:
    """Append or replace today's aggregate row in the history CSV."""
    run_date = run_date or date.today()
    row = {**row, "date": run_date.isoformat()}

    rows: list[dict[str, str]] = []
    if path.exists():
        with path.open("r", encoding="utf-8", newline="") as fh:
            rows = [r for r in csv.DictReader(fh) if r.get("date") != row["date"]]

    rows.append({k: str(row.get(k, "")) for k in HISTORY_FIELDS})
    rows.sort(key=lambda r: r["date"])

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=HISTORY_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def read_history(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))
