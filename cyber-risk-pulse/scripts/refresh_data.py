#!/usr/bin/env python3
"""Refresh dashboard data from live sources.

Thin wrapper around the ingestion CLI used by the scheduled GitHub Actions
workflow. Reads the optional NVD API key from the NVD_API_KEY environment
variable (provided as an Actions secret).
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ingestion.cli import run_pipeline  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


def main() -> int:
    commit = os.environ.get("GITHUB_SHA")
    run_pipeline(
        fixture_mode=False,
        out_dir=REPO / "public" / "data",
        fixtures_dir=REPO / "tests" / "fixtures",
        build_commit=commit,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
