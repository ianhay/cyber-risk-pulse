#!/usr/bin/env python3
"""Build dashboard data from bundled fixtures with no network access.

Used for local development, CI checks and the committed demo dataset. Set
CRP_FIXED_NOW=2026-07-23T13:00:00Z to pin the reference time for reproducible
output; otherwise the current time is used.
"""
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ingestion.cli import run_pipeline  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


def _pinned_now():
    raw = os.environ.get("CRP_FIXED_NOW")
    if not raw:
        return None
    return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)


def main() -> int:
    run_pipeline(
        fixture_mode=True,
        out_dir=REPO / "public" / "data",
        fixtures_dir=REPO / "tests" / "fixtures",
        build_commit=os.environ.get("GITHUB_SHA", "fixture"),
        now=_pinned_now(),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
